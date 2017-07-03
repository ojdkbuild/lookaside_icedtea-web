/* 
Copyright (C) 2013 Red Hat, Inc.

This file is part of IcedTea.

IcedTea is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2.

IcedTea is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with IcedTea; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 USA.

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.
 */

package net.sourceforge.jnlp.util;

import net.sourceforge.jnlp.util.logging.OutputController;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

public class StreamUtils {

    /**
     * Closes a stream, without throwing IOException.
     * In IOException is properly logged and consumed
     * 
     * @param stream the stream that will be closed
     */
    public static void closeSilently(Closeable stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException e) {
                OutputController.getLogger().log(e);
            }
        }
    }

    /**
     * Copy an input stream's contents into an output stream.
     * @param input input stream
     * @param output stream where to copy input
     * @throws java.io.IOException if IO fails
     */
    public static void copyStream(InputStream input, OutputStream output)
            throws IOException {
        byte[] buffer = new byte[1024];
        while (true) {
            int bytesRead = input.read(buffer);
            if (bytesRead == -1) {
                break;
            }
            output.write(buffer, 0, bytesRead);
        }
    }

    public static String readStreamAsString(InputStream stream)  throws IOException {
        return readStreamAsString(stream, false);
    }
    
    public static String readStreamAsString(InputStream stream, String encoding)  throws IOException {
        return readStreamAsString(stream, false, encoding);
    }
    
    public static String readStreamAsString(InputStream stream, boolean includeEndOfLines) throws IOException {
        return readStreamAsString(stream, includeEndOfLines, "UTF-8");
    }
            
    public static String readStreamAsString(InputStream stream, boolean includeEndOfLines, String encoding) throws IOException {
        InputStreamReader is = new InputStreamReader(stream, encoding);
        StringBuilder sb = new StringBuilder();
        BufferedReader br = new BufferedReader(is);
        while (true) {
            String read = br.readLine();
            if (read == null) {
                break;
            }
            sb.append(read);
            if (includeEndOfLines){
                sb.append('\n');
            }

        }

        return sb.toString();
    }
    
    /**
     * This should be workaround for https://en.wikipedia.org/wiki/Spurious_wakeup which real can happen in case of processes.
     * See http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2015-June/032350.html thread
     * @param p process to be waited for
     */
    public static void waitForSafely(Process p) {
        boolean pTerminated = false;
        while (!pTerminated) {
            try {
                p.waitFor();
            } catch (InterruptedException e) {
                OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, e);
            }
            try {
                p.exitValue();
                pTerminated = true;
            } catch (IllegalThreadStateException e) {
                OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, e);
            }
        }
    }
}
