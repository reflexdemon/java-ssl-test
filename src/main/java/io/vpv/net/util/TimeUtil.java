package io.vpv.net.util;

import java.text.DecimalFormat;
import java.util.Date;
import java.util.StringTokenizer;


/**
 * Time utilities.
 *
 * @author Paul Bemowski
 */
public final class TimeUtil {
    public static final String formatTime(long time) {
        if (time < 60) { // if less than 1 min, format as short time
            return formatShortTime(time);
        } else {
            return formatElapsedTime(time);
        }
    }

    /**
     * Formats relatively short times as 0.000 seconds.
     */
    public static final String formatShortTime(long time) {
        DecimalFormat df = new DecimalFormat("0.000");
        double seconds = (double) time / 1000.0;
        return df.format(seconds) + "s";
    }


    /**
     * Returns elapsed time formatted as 000d 00h 00m 00s.
     */
    public static final String formatElapsedTime(long time) {
        StringBuffer sb = new StringBuffer();

        if (time < 0) {
            sb.append("-");
            time = -time;
        }
        DecimalFormat tdf = new DecimalFormat("00");

        DecimalFormat msecf = new DecimalFormat(".000");
        // time is in millis
        // output format should be: 000d 00h 00:00

        if (time == 0)
            return "00m 00s";

        double seconds = (double) time / 1000.0;

        double msec = seconds - Math.floor(seconds);

        int days = (int) Math.floor(seconds / (double) (24 * 60 * 60));
        seconds = seconds - ((double) days * (double) (24 * 60 * 60));

        int hours = (int) Math.floor(seconds / (double) (60 * 60));
        seconds = seconds - ((double) hours * (double) (60 * 60));

        int minutes = (int) Math.floor(seconds / (double) 60);
        seconds = seconds - ((double) minutes * (double) 60);

        if (days > 0)
            sb.append(tdf.format(days) + "d ");
        if (hours > 0)
            sb.append(tdf.format(hours) + "h ");

        if (minutes > 0)
            sb.append(tdf.format(minutes) + "m ");


        sb.append(tdf.format(seconds) + msecf.format(msec) + "s");

        return sb.toString();
    }

    /** */
    public static final String formatLongTimeAgo(long time) {
        return formatLongElapsedTime(System.currentTimeMillis() - time);
    }

    /**
     * Returns elapsed time formatted as 000d 00h 00m 00s.  This method
     * is synchronized because the formatter is not synchronized.
     */
    public static final String formatLongElapsedTime(long time) {
        // time is in millis
        // output format should be: 00 years 00 weeks 00 days 00:00:00
        // System.out.println ("Formatting et: "+time);

        DecimalFormat tdf = new DecimalFormat("00");
        boolean negative = false;
        if (time < 0) {
            time = -time;
            negative = true;
        }

        double seconds = (double) time / 1000.0;

        int years = (int) Math.floor(seconds / (double) (24 * 365 * 3600));
        seconds = seconds - ((double) years * (double) (24 * 365 * 3600));

        int weeks = (int) Math.floor(seconds / (double) (24 * 7 * 3600));
        seconds = seconds - ((double) weeks * (double) (24 * 7 * 3600));

        int days = (int) Math.floor(seconds / (double) (24 * 60 * 60));
        seconds = seconds - ((double) days * (double) (24 * 60 * 60));

        int hours = (int) Math.floor(seconds / (double) (60 * 60));
        seconds = seconds - ((double) hours * (double) (60 * 60));

        int minutes = (int) Math.floor(seconds / (double) 60);
        seconds = seconds - ((double) minutes * (double) 60);

//       System.out.println ("years: "+years+" weeks: "+weeks+" days: "+days+
//                           " hours: "+hours+" minutes: "+minutes+
//                           " seconds: "+seconds);

        StringBuffer sb = new StringBuffer();
        if (negative)
            sb.append("- ");

        if (years > 0)
            sb.append(tdf.format(years) + "years ");
        if (weeks > 0)
            sb.append(tdf.format(weeks) + "weeks ");
        if (days > 0)
            sb.append(tdf.format(days) + "days ");
        if (hours > 0)
            sb.append(tdf.format(hours) + ":");

        if (minutes > 0 || seconds > 0)
            sb.append(tdf.format(minutes) + ":" + tdf.format(seconds));

        return sb.toString();
    }

    /**
     * Returns a string indicating the time since the input
     * date, formatted as xxh xxm if age < 1 day, and xxd xxh if age > 1 day.
     */
    public static final String formatAgeString(Date date) {
        if (date == null)
            return "??";

        long age = System.currentTimeMillis() - date.getTime();

        // should read xxh xxm or xxd xxh
        long day = 1000 * 60 * 60 * 24;
        long hour = 1000 * 60 * 60;
        long minute = 1000 * 60;

        if (age >= day) {
            long days = (long) Math.floor(age / day);
            long remain = age - (days * day);
            long hours = (long) Math.floor(remain / hour);

            return days + "d " + hours + "h";
        } else {
            long hours = (long) Math.floor(age / hour);
            long remain = age - (hours * hour);
            long minutes = (long) Math.floor(remain / minute);
            return hours + "h " + minutes + "m";
        }
    }

    /**
     * Parses a simple time specified as 'Xd Yh Zm As', where X, Y, Z and A are
     * Integers.  This method parses this human readable format into a
     * time value in milliseconds.
     *
     * @param dhm The string formatted time.
     * @return The time in millis.
     */
    public static long parseDHMTime(String dhm) {
        StringTokenizer st = new StringTokenizer(dhm, " ", false);
        long millis = 0;
        while (st.hasMoreTokens()) {
            String tok = st.nextToken();

            String val = tok.substring(0, tok.length() - 1);
            String unit = tok.substring(tok.length() - 1);

            int ival = Integer.parseInt(val);

            if (unit.equalsIgnoreCase("d")) {
                millis = millis + (long) (ival * 24 * 60 * 60 * 1000);
            } else if (unit.equalsIgnoreCase("h")) {
                millis = millis + (long) (ival * 60 * 60 * 1000);
            } else if (unit.equalsIgnoreCase("m")) {
                millis = millis + (long) (ival * 60 * 1000);
            } else if (unit.equalsIgnoreCase("s")) {
                millis = millis + (long) (ival * 1000);
            } else {
                throw new IllegalArgumentException("Invalid value '" + dhm + "'. " +
                        "Day Hour Minute string must be in the " +
                        "format 'Xd Yh Zm As' where " +
                        "X, Y, Z, A are integers.  Any or all tokens can " +
                        "be specified.");
            }
        }
        return millis;
    }
}

