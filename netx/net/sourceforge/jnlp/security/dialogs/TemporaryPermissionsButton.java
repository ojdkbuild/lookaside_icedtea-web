/* Copyright (C) 2014 Red Hat, Inc.

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

package net.sourceforge.jnlp.security.dialogs;

import static net.sourceforge.jnlp.runtime.Translator.R;

import java.awt.Component;
import java.awt.Dialog.ModalityType;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Permission;
import java.util.Collection;
import java.util.HashSet;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import net.sourceforge.jnlp.JNLPFile;
import net.sourceforge.jnlp.config.PathsAndFiles;
import net.sourceforge.jnlp.runtime.JNLPClassLoader.SecurityDelegate;
import net.sourceforge.jnlp.security.policyeditor.PolicyEditor;
import net.sourceforge.jnlp.security.policyeditor.PolicyEditor.PolicyEditorWindow;
import net.sourceforge.jnlp.security.policyeditor.PolicyEditorPermissions;
import net.sourceforge.jnlp.util.logging.OutputController;

public class TemporaryPermissionsButton extends JButton {

    private final JPopupMenu menu;
    private final JButton linkedButton;
    private PolicyEditorWindow policyEditorWindow = null;
    private final JNLPFile file;
    private final SecurityDelegate securityDelegate;
    private final Collection<Permission> temporaryPermissions = new HashSet<>();

    public TemporaryPermissionsButton(final JNLPFile file, final SecurityDelegate securityDelegate, final JButton linkedButton) {
        /* If any of the above parameters are null, then the button cannot function - in particular, a null SecurityDelegate
         * would prevent temporary permissions from being able to be added; a null JNLPFile would prevent PolicyEditor from
         * being launched with a sensible codebase for the current applet; and a null JButton would prevent the Sandbox button
         * from being automatically invoked when a set of temporary permissions are selected by the user.
         */
        super("\u2630");
        this.menu = createPolicyPermissionsMenu();
        this.linkedButton = linkedButton;
        this.file = file;
        this.securityDelegate = securityDelegate;

        if (file == null || securityDelegate == null || linkedButton == null) {
            this.setEnabled(false);
            OutputController.getLogger().log(OutputController.Level.MESSAGE_DEBUG, "Temporary Permissions Button disabled due to null fields."
                    + " file: " + file
                    + ", securityDelegate: " + securityDelegate
                    + ", linkedButton: " + linkedButton);
        } else {
            linkedButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    securityDelegate.addPermissions(temporaryPermissions);
                }
            });
            addMouseListener(new PolicyEditorPopupListener(this));
        }
    }

    private JPopupMenu createPolicyPermissionsMenu() {
        final JPopupMenu policyMenu = new JPopupMenu();

        final JMenuItem launchPolicyEditor = new JMenuItem(R("CertWarnPolicyEditorItem"));
        launchPolicyEditor.addActionListener(new PolicyEditorLaunchListener());
        policyMenu.add(launchPolicyEditor);

        policyMenu.addSeparator();

        final JCheckBoxMenuItem networkAccess = new JCheckBoxMenuItem(R("STempNetwork"));
        networkAccess.addActionListener(new TemporaryPermissionsListener(TemporaryPermissions.getPermissions(PolicyEditorPermissions.NETWORK)));
        policyMenu.add(networkAccess);

        final JCheckBoxMenuItem readLocalFilesAndProperties = new JCheckBoxMenuItem(R("STempReadFilesAndProperties"));
        readLocalFilesAndProperties.addActionListener(new TemporaryPermissionsListener(TemporaryPermissions.getPermissions(PolicyEditorPermissions.Group.ReadFileSystem)));
        policyMenu.add(readLocalFilesAndProperties);

        final JCheckBoxMenuItem writeLocalFilesAndProperties = new JCheckBoxMenuItem(R("STempWriteFilesAndProperties"));
        writeLocalFilesAndProperties.addActionListener(new TemporaryPermissionsListener(TemporaryPermissions.getPermissions(PolicyEditorPermissions.Group.WriteFileSystem)));
        policyMenu.add(writeLocalFilesAndProperties);

        final JCheckBoxMenuItem reflectionOnly = new JCheckBoxMenuItem(R("STempReflectionAndExternal"));
        reflectionOnly.addActionListener(new TemporaryPermissionsListener(TemporaryPermissions.getPermissions(PolicyEditorPermissions.Group.AccessUnownedCode)));
        policyMenu.add(reflectionOnly);

        final JCheckBoxMenuItem allMedia = new JCheckBoxMenuItem(R("STempAllMedia"));
        allMedia.addActionListener(new TemporaryPermissionsListener(TemporaryPermissions.getPermissions(PolicyEditorPermissions.Group.MediaAccess)));
        policyMenu.add(allMedia);

        return policyMenu;
    }

    private class TemporaryPermissionsListener implements ActionListener {
        private Collection<Permission> permissions;

        public TemporaryPermissionsListener(final Collection<Permission> permissions) {
            this.permissions = permissions;
        }

        @Override
        public void actionPerformed(final ActionEvent e) {
            if (!linkedButton.isEnabled()) {
                return;
            }
            AbstractButton checkBox = (AbstractButton) e.getSource();
            if (checkBox.isSelected()) {
                temporaryPermissions.addAll(permissions);
            } else {
                temporaryPermissions.removeAll(permissions);
            }
            menu.setVisible(true);
        }
    }

    private class PolicyEditorLaunchListener implements ActionListener {
        @Override
        public void actionPerformed(final ActionEvent e) {
            final String rawFilepath = PathsAndFiles.JAVA_POLICY.getFullPath();
            String filepath;
            try {
                filepath = new URL(rawFilepath).getPath();
            } catch (final MalformedURLException mfue) {
                filepath = null;
            }

            if (policyEditorWindow == null || policyEditorWindow.getPolicyEditor().isClosed()) {
                policyEditorWindow = PolicyEditor.getPolicyEditorDialog(filepath);
            } else {
                policyEditorWindow.asWindow().toFront();
                policyEditorWindow.asWindow().repaint();
            }
            policyEditorWindow.setModalityType(ModalityType.DOCUMENT_MODAL);
            policyEditorWindow.getPolicyEditor().addNewCodebase(file.getCodeBase().toString());
            policyEditorWindow.asWindow().setVisible(true);
            menu.setVisible(false);
        }
    }

    private class PolicyEditorPopupListener extends MouseAdapter {
        private final Component parent;

        public PolicyEditorPopupListener(final Component parent) {
            this.parent = parent;
        }

        @Override
        public void mouseClicked(final MouseEvent e) {
            menu.show(parent, e.getX(), e.getY());
        }
    }
}
