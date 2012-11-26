package com.wyntersoft.crashreporteranalyzer;

import com.wyntersoft.crashreporteranalyzer.*;

import com.google.protobuf.InvalidProtocolBufferException;
import coop.plausible.crashreporter.CrashReport_pb;
import coop.plausible.crashreporter.CrashReport_pb.CrashReport.BinaryImage;
import coop.plausible.crashreporter.CrashReport_pb.CrashReport.Processor.TypeEncoding;
import coop.plausible.crashreporter.CrashReport_pb.CrashReport.Thread;
import coop.plausible.crashreporter.CrashReport_pb.CrashReport.Thread.StackFrame;
import coop.plausible.crashreporter.CrashReport_pb.CrashReport.Processor;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Date;
import java.lang.Math;

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
        for(BinaryImage image : report.getBinaryImagesList()) {
            if (!image.hasCodeType())
                continue;

            if (image.getCodeType().getEncoding() != TypeEncoding.TYPE_ENCODING_MACH)
                continue;

            if (CpuType.valueOf((int)image.getCodeType().getType()) != null)
                return CpuType.valueOf((int)image.getCodeType().getType());
        }

        switch (report.getSystemInfo().getArchitecture()) {
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
        return String.format("Unknown (%d)", (int)report.getSystemInfo().getArchitecture().getNumber());
    }

    public String getHardwareModel() {
        if (report.hasMachineInfo() && report.getMachineInfo().getModel() != null)
            return report.getMachineInfo().getModel();

        return unknownString;
    }

    public String getCrashReport() {
        StringBuilder sb = new StringBuilder();
        // Preamble
        sb.append("Incident Identifier:   [TODO]\n")
          .append("CrashReporter Key:     [TODO]\n");

        // Machine info
        sb.append(String.format("Hardware Model:        %s\n",getHardwareModel()));

        // Process Info
        String processName = unknownString;
        String processId = unknownString;
        String processPath = unknownString;
        String parentProcessName = unknownString;
        String parentProcessId = unknownString;
        if (report.hasProcessInfo()) {
            if (report.getProcessInfo().getProcessName() != null)
                processName = report.getProcessInfo().getProcessName();

            processId = String.format("%d", report.getProcessInfo().getProcessId());

            if (report.getProcessInfo().hasProcessPath())
                processPath = report.getProcessInfo().getProcessPath();

            if (report.getProcessInfo().getParentProcessName() != null)
                parentProcessName = report.getProcessInfo().getParentProcessName();

            parentProcessId = String.format("%d", report.getProcessInfo().getParentProcessId());
        }

        sb.append(String.format("Process:               %s [%s]\n", processName, processId))
          .append(String.format("Path:                  %s\n", processPath))
          .append(String.format("Identifier:            %s\n", report.getApplicationInfo().getIdentifier()))
          .append(String.format("Version:               %s\n", report.getApplicationInfo().getVersion()))
          .append(String.format("Code Type:             %s\n", getCodeType()))
          .append(String.format("Parent Process         %s [%s]\n", parentProcessName, parentProcessId))
          .append("\n");

        // System info
        String osBuild = unknownString;
        if (report.getSystemInfo().hasOsBuild())
            osBuild = report.getSystemInfo().getOsBuild();

        sb.append(String.format("Date/Time:             %s\n", new Date(report.getSystemInfo().getTimestamp() * 1000)))
          .append(String.format("OS Version:            %s %s (%s)\n", getOperatingSystem(), report.getSystemInfo().getOsVersion(), osBuild))
          .append("Report Version:        104\n")
          .append("\n");

        // Exception code
        sb.append(String.format("Exception Type:        %s\n", report.getSignal().getName()))
          .append(String.format("Exception Codes:       %s at 0x%x\n", report.getSignal().getCode(), report.getSignal().getAddress()));

        for(Thread thread : report.getThreadsList()) {
            if (thread.getCrashed()) {
                sb.append(String.format("Crashed Thread:        %s\n", thread.getThreadNumber()));
                break;
            }
        }
        sb.append("\n");

        // Uncaught Exceptions
        if (report.hasException()) {
            sb.append("Application Specific Information:\n")
              .append(String.format("*** Terminating app due to uncaught exception '%s', reason: '%s'\n",
                    report.getException().getName(), report.getException().getReason()))
              .append("\n");
        }

        // Threads
        Thread crashedThread = null;
        int maxThreadNum = 0;

        for (Thread thread : report.getThreadsList()) {
            if (thread.getCrashed()) {
                sb.append(String.format("Thread %d Crashed:\n", thread.getThreadNumber()));
                crashedThread = thread;
            } else {
                sb.append(String.format("Thread %d:\n", thread.getThreadNumber()));
            }

            long frameIdx = 0;
            for(StackFrame frame : thread.getFramesList()) {
                sb.append(getStackFrameInfo(frame, frameIdx));
                frameIdx++;
            }

            maxThreadNum = Math.max(maxThreadNum, thread.getThreadNumber());

            sb.append("\n");
        }

        // Registers
        if (crashedThread != null) {
            sb.append(String.format("Thread %d crashed with %s Thread State:\n", crashedThread.getThreadNumber(), getCodeType()));

            boolean lp64 = getCpuType().isLp64();
            int regColumn = 0;
            for(Thread.RegisterValue register : crashedThread.getRegistersList()) {
                String reg_fmt;

                /* Use 32-bit or 64-bit fixed width format for the register values */
                if (lp64) {
                    reg_fmt = "%6s: 0x%016x ";
                } else {
                    reg_fmt = "%6s: 0x%08x ";
                }
                /* Remap register names to match Apple's crash reports */
                String regName = register.getName();

                if (report.hasMachineInfo() &&
                    report.getMachineInfo().getProcessor().getEncoding() == TypeEncoding.TYPE_ENCODING_MACH) {

                    Processor processor = report.getMachineInfo().getProcessor();
                    CpuType type = CpuType.valueOf((int)processor.getType());

                    /* Apple uses 'ip' rather than 'r12' on ARM */
                    if (type == CpuType.CPU_TYPE_ARM && regName.equals("r12")) {
                        regName = "ip";
                    }
                }

                sb.append(String.format(reg_fmt, regName, register.getValue()));

                regColumn++;
                if (regColumn == 4) {
                    sb.append("\n");
                    regColumn = 0;
                }
            }

            if (regColumn != 0) {
                sb.append("\n");
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    private String getStackFrameInfo(StackFrame frame, long frameIdx) {
        String imageName = unknownString;
        long baseAddress = 0;
        long pcOffset = 0;

        BinaryImage image = getImageForAddress(frame.getPc());
        if (image != null) {
            imageName = image.getName().substring(image.getName().lastIndexOf('/') + 1);
            baseAddress = image.getBaseAddress();
            pcOffset = frame.getPc() - baseAddress;
        }

        return String.format("%-4d%-36s0x%08x 0x%x + %d\n", frameIdx, imageName, frame.getPc(), baseAddress, pcOffset);
    }

    BinaryImage getImageForAddress(long address) {
        for( BinaryImage image : report.getBinaryImagesList()) {
            if (image.getBaseAddress() <= address && address < (image.getBaseAddress() + image.getSize()))
                return image;
        }
        return null;
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
