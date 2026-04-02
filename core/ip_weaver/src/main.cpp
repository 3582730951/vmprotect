#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_set>

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

namespace {

namespace ast_matchers = clang::ast_matchers;
using clang::CharSourceRange;
using clang::CompoundStmt;
using clang::FunctionDecl;
using clang::LangOptions;
using clang::QualType;
using clang::Rewriter;
using clang::SourceLocation;
using clang::SourceManager;
using clang::SourceRange;
using clang::Stmt;
using clang::tooling::ClangTool;
using clang::tooling::CommonOptionsParser;
using llvm::StringRef;

llvm::cl::OptionCategory kIpWeaverCategory("ip_weaver options");
llvm::cl::opt<std::string> kOutputPath(
    "o",
    llvm::cl::desc("Path to generated .weaved.cpp output file."),
    llvm::cl::cat(kIpWeaverCategory));

llvm::cl::opt<std::string> kTargetNamespace(
    "target-namespace",
    llvm::cl::desc("Only weave function definitions under this namespace."),
    llvm::cl::init("proprietary_hft_core"),
    llvm::cl::cat(kIpWeaverCategory));

[[nodiscard]] bool is_in_target_namespace(const FunctionDecl& function_decl,
                                          llvm::StringRef target_namespace) {
  if (target_namespace.empty()) {
    return false;
  }
  const std::string qualified_name = function_decl.getQualifiedNameAsString();
  if (qualified_name.empty()) {
    return false;
  }

  if (qualified_name == target_namespace) {
    return true;
  }

  if (qualified_name.size() <= target_namespace.size()) {
    return false;
  }

  if (!qualified_name.starts_with(target_namespace)) {
    return false;
  }

  const std::size_t offset = target_namespace.size();
  return qualified_name.compare(offset, 2u, "::") == 0;
}

[[nodiscard]] std::string extract_source_text(const SourceRange& source_range,
                                              const SourceManager& source_manager,
                                              const LangOptions& lang_options) {
  if (source_range.isInvalid()) {
    return {};
  }
  const CharSourceRange char_range = CharSourceRange::getTokenRange(source_range);
  return clang::Lexer::getSourceText(char_range, source_manager, lang_options).str();
}

[[nodiscard]] std::string build_function_signature(const FunctionDecl& function_decl) {
  clang::PrintingPolicy policy(function_decl.getASTContext().getLangOpts());
  policy.SuppressTagKeyword = false;
  policy.FullyQualifiedName = false;

  std::string signature;
  llvm::raw_string_ostream out(signature);
  function_decl.getReturnType().print(out, policy);
  out << ' ' << function_decl.getQualifiedNameAsString() << '(';
  for (unsigned index = 0; index < function_decl.getNumParams(); ++index) {
    const clang::ParmVarDecl* parameter = function_decl.getParamDecl(index);
    if (index > 0u) {
      out << ", ";
    }
    parameter->getType().print(out, policy);
    if (!parameter->getName().empty()) {
      out << ' ' << parameter->getName();
    }
  }
  out << ')';
  return out.str();
}

[[nodiscard]] std::optional<std::string> build_return_statement(const FunctionDecl& function_decl) {
  const QualType return_type = function_decl.getReturnType();
  if (return_type.isNull() || return_type->isDependentType() || return_type->isReferenceType()) {
    return std::nullopt;
  }

  if (return_type->isVoidType()) {
    return "return;";
  }
  if (return_type->isBooleanType()) {
    return "return false;";
  }
  if (return_type->isIntegerType() || return_type->isEnumeralType()) {
    return "return 0;";
  }
  if (return_type->isRealFloatingType()) {
    return "return 0.0;";
  }
  if (return_type->isPointerType() || return_type->isNullPtrType() ||
      return_type->isMemberPointerType()) {
    return "return nullptr;";
  }
  return "return {};";
}

[[nodiscard]] std::string generate_dummy_state_machine_body(
    const std::string& signature_text,
    std::size_t original_body_bytes,
    const std::string& return_statement) {
  std::ostringstream generated;
  generated << "{\n";
  generated << "    // ip_weaver generated skeleton\n";
  generated << "    // signature: " << signature_text << "\n";
  generated << "    // original_body_bytes: " << original_body_bytes << "\n";
  generated << "    int state = 0;\n";
  generated << "    while (true) {\n";
  generated << "        switch (state) {\n";
  generated << "            case 0:\n";
  generated << "                state = 1;\n";
  generated << "                break;\n";
  generated << "            case 1:\n";
  generated << "                " << return_statement << "\n";
  generated << "            default:\n";
  generated << "                state = 1;\n";
  generated << "                break;\n";
  generated << "        }\n";
  generated << "    }\n";
  generated << "}\n";
  return generated.str();
}

class SecureRuleRewriterCallback final : public ast_matchers::MatchFinder::MatchCallback {
 public:
  explicit SecureRuleRewriterCallback(std::string target_namespace)
      : target_namespace_(std::move(target_namespace)) {}

  void set_rewriter(Rewriter* rewriter) noexcept { rewriter_ = rewriter; }

  void run(const ast_matchers::MatchFinder::MatchResult& result) override {
    if (rewriter_ == nullptr || result.Context == nullptr || result.SourceManager == nullptr) {
      return;
    }

    const auto* function_decl = result.Nodes.getNodeAs<FunctionDecl>("secureRuleFunction");
    if (function_decl == nullptr || !function_decl->isThisDeclarationADefinition() ||
        function_decl->isTemplated()) {
      return;
    }
    if (!function_decl->hasBody()) {
      return;
    }
    if (!is_in_target_namespace(*function_decl, target_namespace_)) {
      return;
    }

    const FunctionDecl* canonical = function_decl->getCanonicalDecl();
    if (!rewritten_.insert(canonical).second) {
      return;
    }

    const Stmt* body = function_decl->getBody();
    if (body == nullptr || !llvm::isa<CompoundStmt>(body)) {
      return;
    }

    const SourceLocation begin_location = function_decl->getBeginLoc();
    if (begin_location.isInvalid() || begin_location.isMacroID() ||
        !result.SourceManager->isWrittenInMainFile(begin_location)) {
      return;
    }

    const std::optional<std::string> return_statement = build_return_statement(*function_decl);
    if (!return_statement.has_value()) {
      llvm::errs() << "ip_weaver: skipped unsupported return type in "
                   << function_decl->getQualifiedNameAsString() << "\n";
      return;
    }

    const std::string signature_text = build_function_signature(*function_decl);
    const std::string body_text =
        extract_source_text(body->getSourceRange(), *result.SourceManager, result.Context->getLangOpts());
    const std::string generated_body = generate_dummy_state_machine_body(
        signature_text, body_text.size(), *return_statement);

    const CharSourceRange body_range = CharSourceRange::getTokenRange(body->getSourceRange());
    const bool failed = rewriter_->ReplaceText(body_range, generated_body);
    if (failed) {
      llvm::errs() << "ip_weaver: rewrite failed for "
                   << function_decl->getQualifiedNameAsString() << "\n";
    }
  }

 private:
  std::string target_namespace_;
  Rewriter* rewriter_ = nullptr;
  std::unordered_set<const FunctionDecl*> rewritten_{};
};

class IpWeaverFrontendAction final : public clang::ASTFrontendAction {
 public:
  IpWeaverFrontendAction(std::string output_path, std::string target_namespace)
      : output_path_(std::move(output_path)),
        callback_(std::move(target_namespace)) {
    matcher_.addMatcher(
        ast_matchers::functionDecl(ast_matchers::isDefinition(), ast_matchers::hasBody()).bind(
            "secureRuleFunction"),
        callback_);
  }

  std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance& compiler_instance,
                                                        StringRef /*file_name*/) override {
    rewriter_.setSourceMgr(compiler_instance.getSourceManager(), compiler_instance.getLangOpts());
    callback_.set_rewriter(&rewriter_);
    return matcher_.newASTConsumer();
  }

  void EndSourceFileAction() override {
    const SourceManager& source_manager = rewriter_.getSourceMgr();
    const clang::FileID main_file = source_manager.getMainFileID();
    const clang::RewriteBuffer* rewrite_buffer = rewriter_.getRewriteBufferFor(main_file);

    llvm::StringRef output_text;
    std::string rewritten_storage;
    if (rewrite_buffer != nullptr) {
      rewritten_storage.assign(rewrite_buffer->begin(), rewrite_buffer->end());
      output_text = rewritten_storage;
    } else {
      output_text = source_manager.getBufferData(main_file);
    }

    if (output_path_.empty()) {
      llvm::outs() << output_text;
      return;
    }

    std::error_code error_code;
    llvm::raw_fd_ostream output_stream(output_path_, error_code, llvm::sys::fs::OF_Text);
    if (error_code) {
      llvm::errs() << "ip_weaver: failed to open output file '" << output_path_
                   << "': " << error_code.message() << "\n";
      return;
    }
    output_stream << output_text;
  }

 private:
  std::string output_path_;
  Rewriter rewriter_{};
  SecureRuleRewriterCallback callback_{};
  ast_matchers::MatchFinder matcher_{};
};

class IpWeaverActionFactory final : public clang::tooling::FrontendActionFactory {
 public:
  IpWeaverActionFactory(std::string output_path, std::string target_namespace)
      : output_path_(std::move(output_path)),
        target_namespace_(std::move(target_namespace)) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<IpWeaverFrontendAction>(output_path_, target_namespace_);
  }

 private:
  std::string output_path_;
  std::string target_namespace_;
};

}  // namespace

int main(int argc, const char** argv) {
  llvm::Expected<CommonOptionsParser> expected_parser =
      CommonOptionsParser::create(argc, argv, kIpWeaverCategory);
  if (!expected_parser) {
    llvm::errs() << "ip_weaver: argument parsing failed\n";
    llvm::errs() << llvm::toString(expected_parser.takeError()) << "\n";
    return 1;
  }

  CommonOptionsParser& options_parser = expected_parser.get();
  const auto& source_paths = options_parser.getSourcePathList();
  if (source_paths.empty()) {
    llvm::errs() << "ip_weaver: no input source provided\n";
    return 1;
  }

  if (!kOutputPath.empty() && source_paths.size() != 1u) {
    llvm::errs() << "ip_weaver: -o requires exactly one input source path\n";
    return 1;
  }

  ClangTool tool(options_parser.getCompilations(), source_paths);
  if (kTargetNamespace.empty()) {
    llvm::errs() << "ip_weaver: --target-namespace must not be empty\n";
    return 1;
  }

  IpWeaverActionFactory action_factory(kOutputPath, kTargetNamespace);
  return tool.run(&action_factory);
}
