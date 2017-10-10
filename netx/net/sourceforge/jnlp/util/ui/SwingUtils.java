/* Copyright (C) 2017 Red Hat, Inc.

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

package net.sourceforge.jnlp.util.ui;

import net.sourceforge.jnlp.runtime.JNLPRuntime;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;

public class SwingUtils {

    public static String LABEL_TEXT_PREFIX = "<html>";
    public static String LABEL_TEXT_POSTFIX = "</html>";

    public static void enableDefaultLaF() {
        String className = null;
        if (JNLPRuntime.isWindows()) {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    className = info.getClassName();
                    break;
                }
            }
        } else {
            className = UIManager.getSystemLookAndFeelClassName();
        }
        if (null != className) {
            try {
                UIManager.setLookAndFeel(className);
            } catch (Exception e) {
                // ignore
            }
        }
    }

    //https://stackoverflow.com/a/8149907/314015
    public static String wrapLabelText(String text) {
        if (null == text || text.isEmpty()) {
            return "";
        }
        if (text.length() > LABEL_TEXT_PREFIX.length() && LABEL_TEXT_PREFIX.equalsIgnoreCase(text.substring(0, LABEL_TEXT_PREFIX.length()))) {
            return text;
        }
        return LABEL_TEXT_PREFIX + text + LABEL_TEXT_POSTFIX;
    }

    public static String shortenText(String text, int maxLength) {
        if (null == text) {
            return "";
        }
        if (text.length() < maxLength) {
            return text;
        }
        return text.substring(0, maxLength) + " ...";
    }

    public static String linkify(String url) {
        return "<html><a href=\"" + url + "\">" + url + "</a></html>";
    }

    public static class OpenUrlInBrowserListener extends MouseAdapter {
        private final String url;

        public OpenUrlInBrowserListener(String url) {
            this.url = url;
        }

        @Override
        public void mouseClicked(MouseEvent e) {
            try {
                Desktop.getDesktop().browse(new URI(url));
            } catch (Exception ex) {
                // keep silent
            }
        }
    }
}
