/*
Copyright (C) 2021  Red Hat

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

package net.sourceforge.jnlp.security.dialogs;

import net.sourceforge.jnlp.security.SecurityDialog;
import net.sourceforge.jnlp.security.dialogresults.CertAlias;
import net.sourceforge.jnlp.security.dialogresults.DialogResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;
import java.util.List;

import static net.sourceforge.jnlp.runtime.Translator.R;

public class CertAliasListPanel extends SecurityDialogPanel {
    public CertAliasListPanel(SecurityDialog dialog, String ipAddress, String keyType, List<String> aliases) {
        super(dialog);

        Icon icon = UIManager.getIcon("OptionPane.informationIcon");
        String msg = R("SCertListPrompt", ipAddress, keyType);
        JLabel label = new JLabel("<html>" + msg + "</html>", icon, SwingConstants.LEFT);
        final JComboBox<String> cbox = new JComboBox<>(aliases.toArray(new String[0]));
        cbox.setPreferredSize(new Dimension(200, cbox.getPreferredSize().height));
        cbox.addKeyListener(new KeyAdapter() {
            @Override
            public void keyTyped(KeyEvent e) {
                if (e.getKeyChar() == KeyEvent.VK_ENTER) {
                    parent.setValue(new CertAlias(cbox.getItemAt(cbox.getSelectedIndex())));
                    parent.getViwableDialog().dispose();
                }
            }
        });
        JButton ok = new JButton(R("ButOk"));
        ok.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                parent.setValue(new CertAlias(cbox.getItemAt(cbox.getSelectedIndex())));
                parent.getViwableDialog().dispose();
            }
        });
        JButton cancel = new JButton(R("ButCancel"));
        cancel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                parent.setValue(new CertAlias(null));
                parent.getViwableDialog().dispose();
            }
        });

        parent.getViwableDialog().addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (null == parent.getValue()) {
                    parent.setValue(new CertAlias(null));
                }
            }
        });

        setLayout(new GridBagLayout());

        GridBagConstraints c;
        c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 2;
        c.insets = new Insets(10, 5, 5, 5);
        add(label, c);

        c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 1;
        c.insets = new Insets(10, 5, 5, 5);
        c.weightx = 1.0;
        add(cbox, c);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout());
        buttonPanel.add(cancel);
        buttonPanel.add(ok);

        c = new GridBagConstraints();
        c.anchor = GridBagConstraints.SOUTHEAST;
        c.gridx = 1;
        c.gridy = 3;
        c.insets = new Insets(5, 5, 0, 0);
        c.weightx = 0.0;
        add(buttonPanel, c);

        setBorder(new EmptyBorder(10, 10, 10, 10));

        initialFocusComponent = cbox;
    }

    @Override
    public DialogResult getDefaultNegativeAnswer() {
        return null;
    }

    @Override
    public DialogResult getDefaultPositiveAnswer() {
        return null;
    }

    @Override
    public DialogResult readFromStdIn(String what) {
        return new CertAlias(what);
    }

    @Override
    public String helpToStdIn() {
        return "";
    }

}
