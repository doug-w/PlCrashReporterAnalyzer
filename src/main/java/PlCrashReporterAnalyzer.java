import coop.plausible.crashreporter.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

/**
 * Created with IntelliJ IDEA.
 * User: dwarren
 * Date: 11/25/12
 * Time: 8:40 AM
 * To change this template use File | Settings | File Templates.
 */
public class PlCrashReporterAnalyzer {

    public PlCrashReporterAnalyzer(byte[] buffer) throws Exception
    {
        report = CrashReport_pb.CrashReport.parseFrom(buffer);
    }

    public PlCrashReporterAnalyzer(String path) throws Exception {
        report = CrashReport_pb.CrashReport.parseFrom(new FileInputStream(path));
    }

    public String getOperatingSystem() {
        if (!report.hasSystemInfo()) {
            return "Not Reported";
        }

        switch (report.getSystemInfo().getOperatingSystem()) {
            case MAC_OS_X:
                return "Mac OS X";
            case IPHONE_OS:
                return "iOS";
            case IPHONE_SIMULATOR:
                return "iOS Simulator";
            case OS_UNKNOWN:
                return "Unknown";
        }

        return null;
    }

    private CrashReport_pb.CrashReport report;
}
