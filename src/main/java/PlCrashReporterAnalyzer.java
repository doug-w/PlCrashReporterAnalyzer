package com.wyntersoft.crashreporteranalyzer;

import com.wyntersoft.crashreporteranalyzer.*;

import com.google.protobuf.InvalidProtocolBufferException;
import coop.plausible.crashreporter.CrashReport_pb;
import coop.plausible.crashreporter.CrashReport_pb.CrashReport.BinaryImage;
import coop.plausible.crashreporter.CrashReport_pb.CrashReport.Processor.TypeEncoding;

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
    static final int CPU_ARCH_ABI64	= 0x01000000;		/* 64 bit ABI */

    public enum CpuType {
        CPU_TYPE_ANY        (-1),
        CPU_TYPE_VAX        (1),
        CPU_TYPE_MC680x0	(6),
        CPU_TYPE_X86		(7),
        CPU_TYPE_X86_64     (CPU_TYPE_X86.getValue()|CPU_ARCH_ABI64),
        CPU_TYPE_MC98000	(10),
        CPU_TYPE_HPPA       (11),
        CPU_TYPE_ARM		(12),
        CPU_TYPE_MC88000	(13),
        CPU_TYPE_SPARC		(14),
        CPU_TYPE_I860		(15),
        CPU_TYPE_POWERPC	(18),
        CPU_TYPE_POWERPC64  (CPU_TYPE_POWERPC.getValue()|CPU_ARCH_ABI64);

        public static CpuType valueOf(int value) {
            switch (value) {
                case -1: return CPU_TYPE_ANY;
                case 1: return CPU_TYPE_VAX;
                case 6: return CPU_TYPE_MC680x0;
                case 7: return CPU_TYPE_X86;
                case 7|CPU_ARCH_ABI64: return CPU_TYPE_X86_64;
                case 10: return CPU_TYPE_MC98000;
                case 11: return CPU_TYPE_HPPA;
                case 12: return CPU_TYPE_ARM;
                case 13: return CPU_TYPE_MC88000;
                case 14: return CPU_TYPE_SPARC;
                case 15: return CPU_TYPE_I860;
                case 18: return CPU_TYPE_POWERPC;
                case 18|CPU_ARCH_ABI64: return CPU_TYPE_POWERPC64;

                default: return null;
            }
        }

        private int code;
        CpuType(int c) { code = c;}
        public int getValue() { return code; }

        boolean isLp64() { return (this.getValue() & CPU_ARCH_ABI64) !=0;}

    }

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

    public CpuType getCpuType() {
        for(BinaryImage image : this.report.getBinaryImagesList()) {
            if (!image.hasCodeType())
                continue;

            if (image.getCodeType().getEncoding() != TypeEncoding.TYPE_ENCODING_MACH)
                continue;

            if (CpuType.valueOf((int)image.getCodeType().getType()) != null)
                return CpuType.valueOf((int)image.getCodeType().getType());
        }

        switch (this.report.getSystemInfo().getArchitecture()) {
            case ARMV6:
            case ARMV7:
                return CpuType.CPU_TYPE_ARM;
            case X86_32:
                return CpuType.CPU_TYPE_X86;
            case X86_64:
                return CpuType.CPU_TYPE_X86_64;
            case PPC:
                return CpuType.CPU_TYPE_POWERPC;
        }

        return CpuType.CPU_TYPE_ANY;
    }

    public String getCodeType() {
        switch (getCpuType()) {
            case CPU_TYPE_ARM:
                return "ARM";
            case CPU_TYPE_X86:
                return "X86";
            case CPU_TYPE_X86_64:
                return "X86-64";
            case CPU_TYPE_POWERPC:
                return "PPC";
        }
        return "Unknown ("+(int)this.report.getSystemInfo().getArchitecture().getNumber()+")";
    }

    public String getHardwareModel() {
        if (this.report.hasMachineInfo() && this.report.getMachineInfo().getModel() != null)
            return this.report.getMachineInfo().getModel();

        return unknownString;
    }

    public String getCrashReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("Incident Identifier: [TODO]\n")
                .append("CrashReporter Key:   [TODO]\n")
                .append("Hardware Model:      "+getHardwareModel()+"\n")
                .append(getCodeType()+"\n");


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
