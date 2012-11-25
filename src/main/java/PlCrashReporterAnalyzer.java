package com.wyntersoft.crashreporteranalyzer;

import com.wyntersoft.crashreporteranalyzer.*;

import com.google.protobuf.InvalidProtocolBufferException;
import coop.plausible.crashreporter.*;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

/**
 * Created with IntelliJ IDEA.
 * User: dwarren
 * Date: 11/25/12
 * Time: 8:40 AM
 * To change this template use File | Settings | File Templates.
 */
public class PlCrashReporterAnalyzer {
    private final String unknownString = "???";

    public PlCrashReporterAnalyzer(ByteBuffer buffer) throws InvalidProtocolBufferException, IOException {
        InitFromByteBuffer(buffer);
    }

    public PlCrashReporterAnalyzer(byte[] buffer) throws Exception
    {
        InitFromByteBuffer(ByteBuffer.wrap(buffer));
    }

    public PlCrashReporterAnalyzer(String path) throws Exception {
        FileChannel inChannel = new RandomAccessFile(path, "r").getChannel();

        if (inChannel.size() > Integer.MAX_VALUE) {
            throw new IOException("Dump file too large");
        }

        ByteBuffer buffer = ByteBuffer.allocate((int)inChannel.size());
        int nBytesRead = inChannel.read(buffer);

        InitFromByteBuffer(buffer);
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

    public String getHardwareModel() {
        return unknownString;
    }

    public String getCrashReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("Incident Identifier: [TODO]\n")
                .append("CrashReporter Key:   [TODO]\n")
                .append("Hardware Model:      "+getHardwareModel()+"\n");

        return sb.toString();
    }
    private void InitFromByteBuffer(ByteBuffer buffer) throws InvalidProtocolBufferException, IOException
    {
        this.header = PlCrashReportFileHeader.createFromByteBuffer(buffer);

        if (!this.header.isValid()) {
            throw new IOException("Invalid Crash Report");
        }

        this.report = CrashReport_pb.CrashReport.parseFrom(this.header.getData());

    }

    private PlCrashReportFileHeader header;
    private CrashReport_pb.CrashReport report;
}
