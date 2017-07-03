/* AppletLog.java
   Copyright (C) 2011 Red Hat, Inc.

This file is part of IcedTea.

IcedTea is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

IcedTea is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with IcedTea; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
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
exception statement from your version. */

package net.sourceforge.jnlp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.XMLFormatter;

import net.sourceforge.jnlp.util.FileUtils;

/**
 * This class writes log information to file.
 * 
 * @author Andrew Su (asu@redhat.com, andrew.su@utoronto.ca)
 * 
 */
class AppletLog extends Log {
    private static Logger logger;
    static {
        try {
            // If logging is enabled, we create logger.
            if (enableLogging) {
                String fn = icedteaLogDir + "plugin" + java.lang.System.currentTimeMillis() + ".log";
                FileUtils.createRestrictedFile(new File(fn), true);
                FileHandler fh = new FileHandler(fn, false);
                fh.setFormatter(new XMLFormatter());
                String logClassName = AppletLog.class.getName();
                logger = Logger.getLogger(logClassName);
                logger.setLevel(Level.ALL);
                logger.addHandler(fh);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private AppletLog() {
    }

    /**
     * Log the exception to file.
     * 
     * @param e Exception that was thrown.
     */
    public synchronized static void log(Throwable e) {
        if (enableLogging && logger != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(baos);
            e.printStackTrace(ps);
            logger.log(Level.FINE, baos.toString());
        }
    }
}
