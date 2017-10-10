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

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.util.Arrays;

import static javax.swing.BorderFactory.*;

/**
 * User: alexkasko
 * Date: 5/31/17
 */
public class Boxer {

    public static final int HORIZONTAL_SPACER_WIDTH = 5;
    public static final int VERTICAL_SPACER_HEIGHT = 12;
    public static final int HORIZONTAL_ENDER_WIDTH = 12;

    private static final java.util.List<Color> COLORS = Arrays.asList(
            Color.RED, Color.GREEN, Color.BLUE, Color.YELLOW,
            Color.PINK, Color.ORANGE, Color.MAGENTA, Color.CYAN);

    public static JPanel createTopBox(String title, Border border) {
        JPanel jp = new JPanel();
        BoxLayout bl = new BoxLayout(jp, BoxLayout.X_AXIS);
        jp.setLayout(bl);
        jp.add(Box.createHorizontalGlue());
        jp.setBorder(createTitledBorder(border, title));
        return jp;
    }

    public static JPanel createBottomBox(Component content) {
        JPanel jp = new JPanel();
        BoxLayout bl = new BoxLayout(jp, BoxLayout.X_AXIS);
        jp.setLayout(bl);
        jp.add(Box.createHorizontalGlue());
        jp.setBorder(createCompoundBorder(
                createMatteBorder(1, 0, 0, 0, jp.getBackground().darker()),
                createEmptyBorder(5, 0, 0, 0)));
        jp.add(content);
        return jp;
    }

    public static int equaliseWidth(Component... children) {
        int widthMin = 0;
        int widthPref = 0;
        int widthMax = 0;
        for (Component child : children) {
            if (child.getMinimumSize().getWidth() > widthMin) {
                widthMin = child.getMinimumSize().width;
            }
            if (child.getPreferredSize().getWidth() > widthPref) {
                widthPref = child.getPreferredSize().width;
            }
            if (child.getMaximumSize().getWidth() > widthMax) {
                widthMax = child.getMaximumSize().width;
            }
        }
        for (Component child : children) {
            child.setMinimumSize(new Dimension(widthMin, child.getMinimumSize().height));
            child.setPreferredSize(new Dimension(widthPref, child.getPreferredSize().height));
            child.setMaximumSize(new Dimension(widthMax, child.getMaximumSize().height));
        }
        return widthPref;
    }

    public static void highlightBorders(Component parent) {
        JComponent jparent = (JComponent) parent;
        int i = 0;
        for (Component child : jparent.getComponents()) {
            if (child instanceof  JComponent) {
                JComponent jchild = (JComponent) child;
                highlightBorders(jchild);
                if (child instanceof JPanel /* || child instanceof JButton */) {
                    Color co = COLORS.get(i % COLORS.size());
                    i += 1;
                    jchild.setBorder(createCompoundBorder(createMatteBorder(1, 1, 1, 1, co), jchild.getBorder()));
                    jchild.setToolTipText(jchild.getSize().width + "," + jchild.getSize().height);
                }
            }
        }
    }

    public static Box.Filler slimHorizontalStrut() {
        return slimHorizontalStrut(HORIZONTAL_SPACER_WIDTH);
    }

    public static Box.Filler slimHorizontalStrut(int width) {
        return new Box.Filler(new Dimension(width, 0), new Dimension(width, 0),
                new Dimension(width, 0));
    }

    public static JPanel horizontalPanel() {
        return horizontalPanel(null);
    }

    public static JPanel horizontalPanel(JComponent parent) {
        JPanel panel = new JPanel();
        BoxLayout layout = new BoxLayout(panel, BoxLayout.X_AXIS);
        panel.setLayout(layout);
        if (null != parent) {
            parent.add(panel);
        }
        return panel;
    }

    public static JPanel verticalPanel() {
        return verticalPanel(null);
    }

    public static JPanel verticalPanel(JComponent parent) {
        JPanel panel = new JPanel();
        BoxLayout layout = new BoxLayout(panel, BoxLayout.Y_AXIS);
        panel.setLayout(layout);
        if (null != parent) {
            parent.add(panel);
        }
        return panel;
    }


}
