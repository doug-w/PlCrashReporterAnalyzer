package com.wyntersoft.crashreporteranalyzer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Created with IntelliJ IDEA.
 * User: dwarren
 * Date: 11/25/12
 * Time: 1:06 PM
 * To change this template use File | Settings | File Templates.
 */
public class PlCrashReportFileHeader {
    private String magic;
    private byte version;
    private byte data[];

    private PlCrashReportFileHeader() { }

    public static PlCrashReportFileHeader createFromByteBuffer(ByteBuffer buffer) throws IOException {
        final PlCrashReportFileHeader header = new PlCrashReportFileHeader();

        buffer.rewind();

        byte magic[] = new byte[7];
        buffer.get(magic, 0, 7);

        header.magic = new String(magic);
        header.version = buffer.get();
        header.data = new byte[buffer.remaining()];
        buffer.get(header.data);

        return header;
    }

    public Boolean isValid() {
        return this.magic.equals("plcrash") && (this.version == 1);
    }

    public byte[] getData() {
        return this.data;
    }
}