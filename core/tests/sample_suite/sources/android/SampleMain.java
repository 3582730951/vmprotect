public final class SampleMain {
    private static final String ANCHOR = "EIPPF_SAMPLE_ANCHOR_ANDROID_DEX";

    private static int mixValue(int input) {
        int value = input * 13 + 3;
        if ((value & 1) == 0) {
            value ^= 0x55AA;
        } else {
            value += 27;
        }
        return value + ANCHOR.length();
    }

    public static void main(String[] args) {
        int seed = 31;
        if (args.length > 0) {
            seed += args[0].length();
        }
        int result = mixValue(seed);
        System.out.println(ANCHOR + ":" + result);
    }
}
