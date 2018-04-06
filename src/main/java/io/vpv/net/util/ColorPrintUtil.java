package io.vpv.net.util;

import com.diogonunes.jcdp.color.ColoredPrinter;
import com.diogonunes.jcdp.color.api.Ansi;

/**
 * Created by vprasanna on 4/6/18.
 */
public class ColorPrintUtil {

   public static final ColoredPrinter COLOR_BLUE = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.BLUE)
            .build();
   public static final ColoredPrinter COLOR_BLUE_BOLD = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.BLUE)
            .attribute(Ansi.Attribute.BOLD)
            .build();
   public static final ColoredPrinter COLOR_RED = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.RED)
            .build();
   public static final ColoredPrinter COLOR_RED_BOLD = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.RED)
            .attribute(Ansi.Attribute.BOLD)
            .build();
   public static final ColoredPrinter COLOR_GREEN = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.GREEN)
            .build();
   public static final ColoredPrinter COLOR_GREEN_BOLD = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.GREEN)
            .attribute(Ansi.Attribute.BOLD)
            .build();
   public static final ColoredPrinter COLOR_WHITE = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.WHITE)
            .build();
   public static final ColoredPrinter COLOR_WHITE_BOLD = new ColoredPrinter.Builder(1, false)
            .foreground(Ansi.FColor.WHITE)
            .attribute(Ansi.Attribute.BOLD)
            .build();

    public static void log(final String message) {
        COLOR_BLUE.print(COLOR_BLUE.getDateFormatted() + " ");
        COLOR_BLUE_BOLD.print(message);
//        COLOR_BLUE_BOLD.clear();
    }

    public static void print(final String message, ColoredPrinter cp) {
        cp.print(message);
//        cp.clear();
    }

    public static void println(final String message, ColoredPrinter cp) {
        print(message, cp);
        System.out.println();
    }

    public static void logln(final String message) {
        log(message);
        System.out.println();
    }
    public static void print(final String message) {
        COLOR_BLUE_BOLD.print(message);
//        COLOR_BLUE_BOLD.clear();
    }

    public static void println(final String message) {
        print(message);
        System.out.println();
    }

    public static void printErr(final String message) {
        COLOR_RED.print(message);
//        COLOR_RED.clear();
    }

    public static void printErrln(final String message) {
        printErr(message);
        System.out.println();
    }

    public static void printKeyValue(final String key, final String value) {
        COLOR_GREEN_BOLD.print(key);
        COLOR_WHITE.println(value);
    }
}
