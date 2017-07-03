/*Copyright (C) 2014 Red Hat, Inc.

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

package net.sourceforge.jnlp.security.policyeditor;

import static net.sourceforge.jnlp.runtime.Translator.R;

import java.awt.Color;
import java.awt.Container;
import java.awt.Dialog.ModalityType;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Window;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.swing.AbstractAction;
import javax.swing.AbstractButton;
import javax.swing.Action;
import javax.swing.ActionMap;
import javax.swing.DefaultListModel;
import javax.swing.InputMap;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import net.sourceforge.jnlp.about.AboutDialog;
import net.sourceforge.jnlp.OptionsDefinitions;
import net.sourceforge.jnlp.config.PathsAndFiles;
import net.sourceforge.jnlp.runtime.JNLPRuntime;

import net.sourceforge.jnlp.security.policyeditor.PolicyEditorPermissions.Group;
import net.sourceforge.jnlp.util.FileUtils;
import net.sourceforge.jnlp.util.FileUtils.OpenFileResult;
import net.sourceforge.jnlp.util.docprovider.PolicyEditorTextsProvider;
import net.sourceforge.jnlp.util.docprovider.TextsProvider;
import net.sourceforge.jnlp.util.docprovider.formatters.formatters.PlainTextFormatter;
import net.sourceforge.jnlp.util.logging.OutputController;
import net.sourceforge.jnlp.util.optionparser.OptionParser;

/**
 * This class provides a policy editing tool as a simpler alternate to
 * the JDK PolicyTool. It is much simpler than PolicyTool - only
 * a handful of pre-defined permissions can be enabled or disabled,
 * on a per-codebase basis. There are no considerations for Principals,
 * who signed the code, or custom permissions.
 * 
 * This editor has a very simple idea of a policy file's contents. If any
 * entries are found which it does not recognize, eg 'grant' blocks which
 * have more than zero or one simple codeBase attributes, or 'Principal'
 * or other attributes assigned to the "grant block", or any other type
 * of complication to a "grant block" beyond a single codebase,
 * then all of these pieces of data are disregarded. When the editor saves
 * its work, all of this unrecognized data will be overwritten. Since
 * the editor has no way to display any of these contents anyway, it would
 * be potentially dangerous to allow this information to persist in the
 * policy file even after it has been edited and saved, as this would mean
 * the policy file contents may not be what the user thinks they are.
 * 
 * Comments in policy files are loosely supported, using both block-style
 * comment delimiters and double slashes. Block comments may not, however,
 * be placed on a line with "functional" text on the same line. To be
 * safe, comments should not be adjacent to "functional" text in the file
 * unless those lines are intended to be disregarded, ie commented out.
 * Comments will *not* be preserved when PolicyEditor next saves to the
 * file.
 */
public class PolicyEditor extends JPanel {

    /**
     * Command line switch to print a help message.
     */
    public static final String HELP_FLAG = OptionsDefinitions.OPTIONS.HELP1.option;

    /**
     * Command line switch to specify the location of the policy file.
     * If not given, then the default DeploymentConfiguration path is used.
     */
    public static final String FILE_FLAG = OptionsDefinitions.OPTIONS.FILE.option;

    /**
     * Command line switch to specify a new codebase entry to be made.
     * Can only be used once, presently.
     */
    public static final String CODEBASE_FLAG = OptionsDefinitions.OPTIONS.CODEBASE.option;

    
      private boolean closed = false;
    private final Map<PolicyEditorPermissions, JCheckBox> checkboxMap = new TreeMap<>();
    private final List<JCheckBoxWithGroup> groupBoxList = new ArrayList<>(Group.values().length);
    private final JScrollPane scrollPane = new JScrollPane();
    private final DefaultListModel<String> listModel = new DefaultListModel<>();
    private final JList<String> list = new JList<>(listModel);
    private final JButton okButton = new JButton(), closeButton = new JButton(),
            addCodebaseButton = new JButton(), removeCodebaseButton = new JButton();
    private final JFileChooser fileChooser;
    private CustomPolicyViewer cpViewer = null;
    /**
     * See showChangesSavedDialog/showCouldNotSaveDialog. This weak reference is needed because
     * there is a modal child dialog which can sometimes appear after the editor has been closed
     * and disposed. In this case, its parent should be set to 'null', but otherwise the parent
     * should be the editor so that the dialog is modal.
     */
    private final WeakReference<PolicyEditor> parentPolicyEditor = new WeakReference<>(this);
    public final PolicyEditorController policyEditorController = new PolicyEditorController();

    private final ActionListener okButtonAction, addCodebaseButtonAction,
            removeCodebaseButtonAction, newButtonAction, openButtonAction, openDefaultButtonAction, saveAsButtonAction, viewCustomButtonAction,
            renameCodebaseButtonAction, copyCodebaseButtonAction, pasteCodebaseButtonAction,
            policyEditorHelpButtonAction, aboutPolicyEditorButtonAction, aboutItwButtonAction;
    private final ActionListener closeButtonAction;

    private static class JCheckBoxWithGroup extends JCheckBox {

        private final PolicyEditorPermissions.Group group;

        private JCheckBoxWithGroup(Group group) {
            super(group.getTitle());
            this.group = group;
        }

        public Group getGroup() {
            return group;
        }

        private void setState(final Map<PolicyEditorPermissions, Boolean> map) {
            final List<ActionListener> backup = new LinkedList<>();
            for (final ActionListener l : this.getActionListeners()) {
                backup.add(l);
                this.removeActionListener(l);
            }
            final int i = group.getState(map);
            this.setBackground(getParent().getBackground());
            if (i > 0) {
                this.setSelected(true);
            }
            if (i < 0) {
                this.setSelected(false);
            }
            if (i == 0) {
                this.setBackground(Color.yellow);
                this.setSelected(false);
            }

            for (final ActionListener al : backup) {
                this.addActionListener(al);
            }
        }
    }

    public PolicyEditor(final String filepath) {
        super();
        setLayout(new GridBagLayout());

        for (final PolicyEditorPermissions perm : PolicyEditorPermissions.values()) {
            final JCheckBox box = new JCheckBox();
            box.setText(perm.getName());
            box.setToolTipText(perm.getDescription());
            checkboxMap.put(perm, box);
        }

        setFile(filepath);
        if (filepath != null) {
            try {
                policyEditorController.openAndParsePolicyFile();
            } catch (final FileNotFoundException fnfe) {
                OutputController.getLogger().log(fnfe);
                FileUtils.showCouldNotOpenDialog(PolicyEditor.this, R("PECouldNotOpen"));
            } catch (final IOException | InvalidPolicyException e) {
                OutputController.getLogger().log(e);
                OutputController.getLogger().log(OutputController.Level.ERROR_ALL, R("RCantOpenFile", policyEditorController.getFile().getPath()));
                FileUtils.showCouldNotOpenDialog(PolicyEditor.this, R("PECouldNotOpen"));
            }
            try {
                invokeRunnableOrEnqueueAndWait(new Runnable() {
                    @Override
                    public void run() {
                        for (final String codebase : policyEditorController.getCodebases()) {
                            final String model;
                            if (codebase.isEmpty()) {
                                model = R("PEGlobalSettings");
                            } else {
                                model = codebase;
                            }
                            if (!listModel.contains(model)) {
                                listModel.addElement(model);
                            }
                        }
                        addNewCodebase("");
                    }
                });
            } catch (final InvocationTargetException | InterruptedException e) {
                OutputController.getLogger().log(e);
            }
        }
        setChangesMade(false);

        fileChooser = new JFileChooser(policyEditorController.getFile());
        fileChooser.setFileHidingEnabled(false);

        okButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent event) {
                if (policyEditorController.getFile() == null) {
                    final int choice = fileChooser.showOpenDialog(PolicyEditor.this);
                    if (choice == JFileChooser.APPROVE_OPTION) {
                        PolicyEditor.this.setFile(fileChooser.getSelectedFile().getAbsolutePath());
                    }
                }

                // May still be null if user cancelled the file chooser
                if (policyEditorController.getFile() != null) {
                    savePolicyFile();
                }
            }
        };
        okButton.setText(R("ButApply"));
        okButton.addActionListener(okButtonAction);

        addCodebaseButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                addNewCodebaseInteractive();
            }
        };
        addCodebaseButton.setText(R("PEAddCodebase"));
        addCodebaseButton.addActionListener(addCodebaseButtonAction);

        removeCodebaseButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                removeCodebase(getSelectedCodebase());
            }
        };
        removeCodebaseButton.setText(R("PERemoveCodebase"));
        removeCodebaseButton.addActionListener(removeCodebaseButtonAction);

        newButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                if (!promptOnSaveChangesMade(false)) return;
                setFile(null);
                setChangesMade(false);
            }
        };

        openButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                if (!promptOnSaveChangesMade(true)) return;
                final int choice = fileChooser.showOpenDialog(PolicyEditor.this);
                if (choice == JFileChooser.APPROVE_OPTION) {
                    PolicyEditor.this.setFile(fileChooser.getSelectedFile().getAbsolutePath());
                    openAndParsePolicyFile();
                }
            }
        };
        
         openDefaultButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                if (!promptOnSaveChangesMade(true)) {
                    return;
                }
                try {
                    PolicyEditor.this.setFile(getDefaultPolicyFilePath());
                    PolicyEditor.this.getFile().createNewFile();
                } catch (final IOException ex) {
                    OutputController.getLogger().log(ex);
                } catch (final URISyntaxException ex) {
                    OutputController.getLogger().log(ex);
                }
                openAndParsePolicyFile();
            }
        };

        saveAsButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                final int choice = fileChooser.showSaveDialog(PolicyEditor.this);
                if (choice == JFileChooser.APPROVE_OPTION) {
                    PolicyEditor.this.setFile(fileChooser.getSelectedFile().getAbsolutePath());
                    setChangesMade(true);
                    savePolicyFile();
                }
            }
        };

        renameCodebaseButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                final String oldCodebase = getSelectedCodebase();
                if (oldCodebase.isEmpty()) {
                    return;
                }
                String newCodebase = "";
                while (!validateCodebase(newCodebase) || policyEditorController.getCopyOfPermissions().containsKey(newCodebase)) {
                    newCodebase = JOptionPane.showInputDialog(PolicyEditor.this, R("PERenameCodebase"), oldCodebase);
                    if (newCodebase == null) {
                        return;
                    }
                }
                renameCodebase(oldCodebase, newCodebase);
            }
        };

        copyCodebaseButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                copyCodebase(getSelectedCodebase());
            }
        };

        pasteCodebaseButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                String clipboardCodebase = null;
                try {
                    clipboardCodebase = policyEditorController.getCodebaseFromClipboard();
                    final String newCodebase;
                    if (getCodebases().contains(clipboardCodebase)) {
                        String cb = "";
                        while (!validateCodebase(cb) || policyEditorController.getCopyOfPermissions().containsKey(cb)) {
                            cb = JOptionPane.showInputDialog(PolicyEditor.this, R("PEPasteCodebase"), "http://");
                            if (cb == null) {
                                return;
                            }
                        }
                        newCodebase = cb;
                    } else {
                        newCodebase = clipboardCodebase;
                    }
                    if (validateCodebase(newCodebase)) {
                        pasteCodebase(newCodebase);
                    }
                } catch (final UnsupportedFlavorException ufe) {
                    OutputController.getLogger().log(ufe);
                    showClipboardErrorDialog();
                } catch (final InvalidPolicyException ipe) {
                    OutputController.getLogger().log(ipe);
                    showInvalidPolicyExceptionDialog(clipboardCodebase);
                } catch (final IOException ioe) {
                    OutputController.getLogger().log(ioe);
                    showCouldNotAccessClipboardDialog();
                }
            }
        };

        viewCustomButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                invokeRunnableOrEnqueueLater(new Runnable() {
                    @Override
                    public void run() {
                        String codebase = getSelectedCodebase();
                        if (codebase == null) {
                            return;
                        }
                        if (cpViewer == null) {
                            cpViewer = new CustomPolicyViewer(PolicyEditor.this, codebase);
                            cpViewer.setVisible(true);
                        } else {
                            cpViewer.toFront();
                            cpViewer.repaint();
                        }
                    }
                });
            }
        };

        policyEditorHelpButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                new PolicyEditorAboutDialog(R("PEHelpDialogTitle"), R("PEHelpDialogContent")).setVisible(true);
            }
        };

        aboutPolicyEditorButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                boolean modal = getModality();
                AboutDialog.display(modal, TextsProvider.POLICY_EDITOR,AboutDialog.ShowPage.HELP);
            }
        };
        
         aboutItwButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                boolean modal = getModality();
                AboutDialog.display(modal, TextsProvider.POLICY_EDITOR);
            }
        };

        closeButtonAction = new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent event) {
                final Window parentWindow = SwingUtilities.getWindowAncestor(PolicyEditor.this);
                if (parentWindow instanceof PolicyEditorWindow) {
                    ((PolicyEditorWindow) parentWindow).quit();
                }
            }
        };
        closeButton.setText(R("ButClose"));
        closeButton.addActionListener(closeButtonAction);

        setupLayout();
    }

    private static String getDefaultPolicyFilePath() throws URISyntaxException {
        return new File(new URI(PathsAndFiles.JAVA_POLICY.getFullPath())).getAbsolutePath();
    }
    
    private boolean getModality() {
        boolean modal = false;
        Container parent = PolicyEditor.this;
        while (true) {
            if (parent == null) {
                break;
            }
            if (parent instanceof JDialog) {
                modal = ((JDialog) parent).isModal();
                break;
            }
            parent = parent.getParent();
        }
        return modal;
    }

    /**
     *
     * @param async use asynchronous saving, which displays a progress dialog, or use synchronous, which blocks the
     *              EDT but allows for eg the on-disk file to be changed without resorting to a busy-wait loop
     * @return false iff the user wishes to cancel the operation and keep the current editor state
     */
    private boolean promptOnSaveChangesMade(final boolean async) {
        if (policyEditorController.changesMade()) {
            final int save = JOptionPane.showConfirmDialog(this, R("PESaveChanges"));
            if (save == JOptionPane.YES_OPTION) {
                if (policyEditorController.getFile() == null) {
                    final int choice = fileChooser.showSaveDialog(this);
                    if (choice == JFileChooser.APPROVE_OPTION) {
                        this.setFile(fileChooser.getSelectedFile().getAbsolutePath());
                    } else if (choice == JFileChooser.CANCEL_OPTION) {
                        return false;
                    }
                }
                if (async) {
                    savePolicyFile();
                } else {
                    try {
                        policyEditorController.savePolicyFile();
                    } catch (final IOException e) {
                        showCouldNotSaveDialog();
                    }
                }
            } else if (save == JOptionPane.CANCEL_OPTION) {
                return false;
            }
        }
        return true;
    }

    public void setFile(final String filepath) {
        if (filepath != null) {
            policyEditorController.setFile(new File(filepath));
        } else {
            policyEditorController.setFile(null);
            resetCodebases();
            addNewCodebase("");
        }
        setParentWindowTitle(getWindowTitleForStatus());
    }

    private void setParentWindowTitle(final String title) {
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                final Window parent = SwingUtilities.getWindowAncestor(PolicyEditor.this);
                if (!(parent instanceof PolicyEditorWindow)) {
                    return;
                }
                final PolicyEditorWindow window = (PolicyEditorWindow) parent;
                window.setTitle(title);
            }
        });
    }

    private String getWindowTitleForStatus() {
        final String filepath;
        final File file = getFile();
        if (file != null) {
            filepath = file.getPath();
        } else {
            filepath = null;
        }
        final String titleAndPath;
        if (filepath != null) {
            titleAndPath = R("PETitleWithPath", filepath);
        } else {
            titleAndPath = R("PETitle");
        }
        final String result;
        if (policyEditorController.changesMade()) {
            result = R("PETitleWithChangesMade", titleAndPath);
        } else {
            result = titleAndPath;
        }
        return result;
    }

    private String getSelectedCodebase() {
        final String codebase = list.getSelectedValue();
        if (codebase == null || codebase.isEmpty()) {
            return null;
        }
        if (codebase.equals(R("PEGlobalSettings"))) {
            return "";
        }
        return codebase;
    }

    private static void preparePolicyEditorWindow(final PolicyEditorWindow w, final PolicyEditor e) {
        w.setModalityType(ModalityType.MODELESS); //at least some default
        w.setPolicyEditor(e);
        w.setTitle(R("PETitle"));
        w.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        w.setJMenuBar(createMenuBar(w.getPolicyEditor()));
        setupPolicyEditorWindow(w.asWindow(), w.getPolicyEditor());
    }

    private static void setupPolicyEditorWindow(final Window window, final PolicyEditor editor) {
        window.add(editor);
        window.pack();
        editor.setVisible(true);

        window.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(final WindowEvent e) {
                ((PolicyEditorWindow) window).quit();
            }
        });
    }

    public static interface PolicyEditorWindow {

        public void setTitle(String s);

        public void setDefaultCloseOperation(int i);

        public PolicyEditor getPolicyEditor();

        public void setPolicyEditor(PolicyEditor e);

        public void setJMenuBar(JMenuBar menu);

        public Window asWindow();

        public void setModalityType(ModalityType modalityType);

        public void quit();
    }

    private static class PolicyEditorFrame extends JFrame implements PolicyEditorWindow {

        private PolicyEditor editor;

        private PolicyEditorFrame(final PolicyEditor editor) {
            super();
            preparePolicyEditorWindow((PolicyEditorWindow) this, editor);
        }

        @Override
        public final void setTitle(String title) {
            super.setTitle(title);
        }

        @Override
        public final PolicyEditor getPolicyEditor() {
            return editor;
        }

        @Override
        public final void setPolicyEditor(final PolicyEditor e) {
            editor = e;
        }

        @Override
        public final void setDefaultCloseOperation(final int operation) {
            super.setDefaultCloseOperation(operation);
        }

        @Override
        public final void setJMenuBar(final JMenuBar menu) {
            super.setJMenuBar(menu);
        }

        @Override
        public final Window asWindow() {
            return this;
        }

        @Override
        public void setModalityType(final ModalityType type) {
            //no op for frame
        }

        @Override
        public void quit() {
            policyEditorWindowQuit(this);
        }
    }

    /*
     * Casting a Window to PolicyEditorWindow is not generally safe - be sure that
     * the argument passed to this method is actually a PolicyEditorDialog or PolicyEditorFrame.
     */
    private static void policyEditorWindowQuit(final Window window) {
        final PolicyEditor editor = ((PolicyEditorWindow) window).getPolicyEditor();
        editor.parentPolicyEditor.clear();
        if (editor.policyEditorController.changesMade()) {
            final int save = JOptionPane.showConfirmDialog(window, R("PESaveChanges"));
            if (save == JOptionPane.YES_OPTION) {
                if (editor.policyEditorController.getFile() == null) {
                    final int choice = editor.fileChooser.showSaveDialog(window);
                    if (choice == JFileChooser.APPROVE_OPTION) {
                        editor.setFile(editor.fileChooser.getSelectedFile().getAbsolutePath());
                    } else if (choice == JFileChooser.CANCEL_OPTION) {
                        return;
                    }
                }
                try {
                    editor.policyEditorController.savePolicyFile();
                } catch (final IOException e) {
                    OutputController.getLogger().log(e);
                    editor.showCouldNotSaveDialog();
                    return;
                }
            } else if (save == JOptionPane.CANCEL_OPTION) {
                return;
            }
        }
        editor.setClosed();
        window.dispose();
    }

    public static PolicyEditorWindow getPolicyEditorFrame(final String filepath) {
        return new PolicyEditorFrame(new PolicyEditor(filepath));
    }

    private static class PolicyEditorDialog extends JDialog implements PolicyEditorWindow {

        private PolicyEditor editor;

        private PolicyEditorDialog(final PolicyEditor editor) {
            super();
            preparePolicyEditorWindow((PolicyEditorWindow) this, editor);
        }

        @Override
        public final void setTitle(final String title) {
            super.setTitle(title);
        }

        @Override
        public final PolicyEditor getPolicyEditor() {
            return editor;
        }

        @Override
        public final void setPolicyEditor(final PolicyEditor e) {
            editor = e;
        }

        @Override
        public final void setDefaultCloseOperation(final int operation) {
            super.setDefaultCloseOperation(operation);
        }

        @Override
        public final void setJMenuBar(final JMenuBar menu) {
            super.setJMenuBar(menu);
        }

        @Override
        public final Window asWindow() {
            return this;
        }

        @Override
        public void setModalityType(final ModalityType type) {
            super.setModalityType(type);
        }

        @Override
        public void quit() {
            policyEditorWindowQuit(this);
        }
    }

    public static PolicyEditorWindow getPolicyEditorDialog(final String filepath) {
        return new PolicyEditorDialog(new PolicyEditor(filepath));
    }

    private void setClosed() {
        closed = true;
    }

    /**
     * Check if the PolicyEditor instance has been visually closed
     * @return if the PolicyEditor instance has been closed
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Called by the Custom Policy Viewer on its parent Policy Editor when
     * the Custom Policy Viewer is closing
     */
    void customPolicyViewerClosing() {
        cpViewer = null;
    }

    /**
     * Add a new codebase to the editor's model. If the codebase is not a valid URL,
     * the codebase is not added.
     * @param codebase to be added
     */
    public void addNewCodebase(final String codebase) {
        if (!codebase.isEmpty() && !validateCodebase(codebase)) {
            OutputController.getLogger().log("Could not add codebase " + codebase);
            return;
        }
        final String model;
        if (codebase.isEmpty()) {
            model = R("PEGlobalSettings");
        } else {
            model = codebase;
        }
        policyEditorController.addCodebase(codebase);
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                if (!listModel.contains(model)) {
                    listModel.addElement(model);
                    setChangesMade(true);
                }
                list.setSelectedValue(model, true);
                updateCheckboxes(codebase);
            }
        });
    }

    private static boolean validateCodebase(final String codebase) {
        try {
            new URL(codebase);
        } catch (final MalformedURLException mue) {
            return false;
        }
        return true;
    }


    public File getFile() {
        return policyEditorController.getFile();
    }

    /**
     * Display an input dialog, which will disappear when the user enters a valid URL
     * or when the user presses cancel. If an invalid URL is entered, the dialog reappears.
     * When a valid URL is entered, it is used to create a new codebase entry in the editor's
     * policy file model.
     */
    public void addNewCodebaseInteractive() {
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                String codebase = "";
                while (!validateCodebase(codebase)) {
                    codebase = JOptionPane.showInputDialog(PolicyEditor.this, R("PECodebasePrompt"), "http://");
                    if (codebase == null) {
                        return;
                    }
                }
                addNewCodebase(codebase);
            }
        });
    }

    /**
     * Remove a codebase from the editor's model
     * @param codebase to be removed
     */
    public void removeCodebase(final String codebase) {
        if (codebase.equals(R("PEGlobalSettings")) || codebase.isEmpty()) {
            return;
        }
        int previousIndex = list.getSelectedIndex() - 1;
        if (previousIndex < 0) {
            previousIndex = 0;
        }
        policyEditorController.removeCodebase(codebase);
        final int fIndex = previousIndex;
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                listModel.removeElement(codebase);
                list.setSelectedIndex(fIndex);
            }
        });
        setChangesMade(true);
    }

    /**
     * Rename a codebase, preserving its permissions
     * @param oldCodebase the codebase to rename
     * @param newCodebase the new name for the codebase
     */
    public void renameCodebase(final String oldCodebase, final String newCodebase) {
        final Map<PolicyEditorPermissions, Boolean> permissions = getPermissions(oldCodebase);
        final Collection<CustomPermission> customPermissions = getCustomPermissions(oldCodebase);

        removeCodebase(oldCodebase);
        addNewCodebase(newCodebase);

        for (final Map.Entry<PolicyEditorPermissions, Boolean> entry : permissions.entrySet()) {
            setPermission(newCodebase, entry.getKey(), entry.getValue());
        }

        for (final CustomPermission permission : customPermissions) {
            addCustomPermission(newCodebase, permission);
        }

        updateCheckboxes(newCodebase);
    }

    /**
     * Copy a codebase to the system clipboard, preserving its permissions
     * @param codebase the codebase to copy
     */
    public void copyCodebase(final String codebase) {
        if (!getCodebases().contains(codebase)) {
            return;
        }
        policyEditorController.copyCodebaseToClipboard(codebase);
    }

    /**
     * Paste a codebase entry from the system clipboard with a new codebase name
     */
    public void pasteCodebase(final String newCodebase) throws UnsupportedFlavorException, InvalidPolicyException, IOException {
        final Map<PolicyEditorPermissions, Boolean> permissions = policyEditorController.getPermissionsFromClipboard();
        final Set<CustomPermission> customPermissions = policyEditorController.getCustomPermissionsFromClipboard();
        addNewCodebase(newCodebase);
        for (final Map.Entry<PolicyEditorPermissions, Boolean> entry : permissions.entrySet()) {
            policyEditorController.setPermission(newCodebase, entry.getKey(), entry.getValue());
        }
        policyEditorController.addCustomPermissions(newCodebase, customPermissions);
        setChangesMade(true);
        updateCheckboxes(newCodebase);
    }

    public Set<String> getCodebases() {
        return policyEditorController.getCodebases();
    }

    public void setPermission(final String codebase, final PolicyEditorPermissions permission, final boolean state) {
        policyEditorController.setPermission(codebase, permission, state);
    }

    public Map<PolicyEditorPermissions, Boolean> getPermissions(final String codebase) {
        return policyEditorController.getPermissions(codebase);
    }

    public void addCustomPermission(final String codebase, final CustomPermission permission) {
        policyEditorController.addCustomPermission(codebase, permission);
    }

    public Collection<CustomPermission> getCustomPermissions(final String codebase) {
        return policyEditorController.getCustomPermissions(codebase);
    }

    public void clearCustomPermissions(final String codebase) {
        policyEditorController.clearCustomCodebase(codebase);
    }

    private void invokeRunnableOrEnqueueLater(final Runnable runnable) {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeLater(runnable);
        }
    }

    private void invokeRunnableOrEnqueueAndWait(final Runnable runnable) throws InvocationTargetException, InterruptedException {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    /**
     * Update the checkboxes to show the permissions granted to the specified codebase
     * @param codebase whose permissions to display
     */
    private void updateCheckboxes(final String codebase) {
        try {
            invokeRunnableOrEnqueueAndWait(new Runnable() {
                @Override
                public void run() {
                    updateCheckboxesImpl(codebase);
                }
            });
        } catch (InterruptedException ex) {
            OutputController.getLogger().log(ex);
        } catch (InvocationTargetException ex) {
            OutputController.getLogger().log(ex);
        }
    }

    private void updateCheckboxesImpl(final String codebase) {
        if (!getCodebases().contains(codebase)) {
            return;
        }
        final Map<PolicyEditorPermissions, Boolean> map = policyEditorController.getCopyOfPermissions().get(codebase);
        for (final PolicyEditorPermissions perm : PolicyEditorPermissions.values()) {
            final JCheckBox box = checkboxMap.get(perm);
            for (final ActionListener l : box.getActionListeners()) {
                box.removeActionListener(l);
            }
            final boolean state = policyEditorController.getPermission(codebase, perm);
            for (final JCheckBoxWithGroup jg : groupBoxList) {
                jg.setState(map);
            }
            box.setSelected(state);
            box.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(final ActionEvent e) {
                    setChangesMade(true);
                    policyEditorController.setPermission(codebase, perm, box.isSelected());
                    for (JCheckBoxWithGroup jg : groupBoxList) {
                        jg.setState(map);
                    }
                }
            });
        }
    }

    /**
     * Set a mnemonic key for a menu item or button
     * @param button the component for which to set a mnemonic
     * @param mnemonic the mnemonic to set
     */
    private static void setButtonMnemonic(final AbstractButton button, final String mnemonic) {
        if (mnemonic.length() != 1) {
            OutputController.getLogger().log(OutputController.Level.WARNING_DEBUG, "Could not set mnemonic \"" + mnemonic + "\" for " + button);
            return;
        }
        final char ch = mnemonic.charAt(0);
        button.setMnemonic(ch);
    }

    private static void setMenuItemAccelerator(final JMenuItem menuItem, final String accelerator) {
        final KeyStroke ks = KeyStroke.getKeyStroke(accelerator);
        menuItem.setAccelerator(ks);
    }

    private static JMenuBar createMenuBar(final PolicyEditor editor) {
        final JMenuBar menuBar = new JMenuBar();

        final JMenu fileMenu = new JMenu(R("PEFileMenu"));
        setButtonMnemonic(fileMenu, R("PEFileMenuMnemonic"));

        final JMenuItem newItem = new JMenuItem(R("PENewMenuItem"));
        setButtonMnemonic(newItem, R("PENewMenuItemMnemonic"));
        setMenuItemAccelerator(newItem, R("PENewMenuItemAccelerator"));
        newItem.addActionListener(editor.newButtonAction);
        fileMenu.add(newItem);

        final JMenuItem openItem = new JMenuItem(R("PEOpenMenuItem"));
        setButtonMnemonic(openItem, R("PEOpenMenuItemMnemonic"));
        setMenuItemAccelerator(openItem, R("PEOpenMenuItemAccelerator"));
        openItem.addActionListener(editor.openButtonAction);
        fileMenu.add(openItem);

        final JMenuItem openDefaultItem = new JMenuItem(R("PEOpenDefaultMenuItem"));
        setButtonMnemonic(openDefaultItem, R("PEOpenDefaultMenuItemMnemonic"));
        setMenuItemAccelerator(openDefaultItem, R("PEOpenDefaultMenuItemAccelerator"));
        openDefaultItem.addActionListener(editor.openDefaultButtonAction);
        fileMenu.add(openDefaultItem);

        final JMenuItem saveItem = new JMenuItem(R("PESaveMenuItem"));
        setButtonMnemonic(saveItem, R("PESaveMenuItemMnemonic"));
        setMenuItemAccelerator(saveItem, R("PESaveMenuItemAccelerator"));
        saveItem.addActionListener(editor.okButtonAction);
        fileMenu.add(saveItem);

        final JMenuItem saveAsItem = new JMenuItem(R("PESaveAsMenuItem"));
        setButtonMnemonic(saveAsItem, R("PESaveAsMenuItemMnemonic"));
        setMenuItemAccelerator(saveAsItem, R("PESaveAsMenuItemAccelerator"));
        saveAsItem.addActionListener(editor.saveAsButtonAction);
        fileMenu.add(saveAsItem);
        
        final JMenuItem exitItem = new JMenuItem(R("PEExitMenuItem"));
        setButtonMnemonic(exitItem, R("PEExitMenuItemMnemonic"));
        setMenuItemAccelerator(exitItem, R("PEExitMenuItemAccelerator"));
        exitItem.addActionListener(editor.closeButtonAction);
        fileMenu.add(exitItem);
        menuBar.add(fileMenu);

        final JMenu codebaseMenu = new JMenu(R("PECodebaseMenu"));
        setButtonMnemonic(codebaseMenu, R("PECodebaseMenuMnemonic"));

        final JMenuItem addNewCodebaseItem = new JMenuItem(R("PEAddCodebaseItem"));
        setButtonMnemonic(addNewCodebaseItem, R("PEAddCodebaseItemMnemonic"));
        setMenuItemAccelerator(addNewCodebaseItem, R("PEAddCodebaseItemAccelerator"));
        addNewCodebaseItem.addActionListener(editor.addCodebaseButtonAction);
        codebaseMenu.add(addNewCodebaseItem);

        final JMenuItem removeCodebaseItem = new JMenuItem(R("PERemoveCodebaseItem"));
        setButtonMnemonic(removeCodebaseItem, R("PERemoveCodebaseItemMnemonic"));
        setMenuItemAccelerator(removeCodebaseItem, R("PERemoveCodebaseItemAccelerator"));
        removeCodebaseItem.addActionListener(editor.removeCodebaseButtonAction);
        codebaseMenu.add(removeCodebaseItem);

        codebaseMenu.addSeparator();

        final JMenuItem renameCodebaseItem = new JMenuItem(R("PERenameCodebaseItem"));
        setButtonMnemonic(renameCodebaseItem, R("PERenameCodebaseItemMnemonic"));
        setMenuItemAccelerator(renameCodebaseItem, R("PERenameCodebaseItemAccelerator"));
        renameCodebaseItem.addActionListener(editor.renameCodebaseButtonAction);
        codebaseMenu.add(renameCodebaseItem);

        final JMenuItem copyCodebaseItem = new JMenuItem(R("PECopyCodebaseItem"));
        setButtonMnemonic(copyCodebaseItem, R("PECopyCodebaseItemMnemonic"));
        setMenuItemAccelerator(copyCodebaseItem, R("PECopyCodebaseItemAccelerator"));
        copyCodebaseItem.addActionListener(editor.copyCodebaseButtonAction);
        codebaseMenu.add(copyCodebaseItem);
        menuBar.add(codebaseMenu);

        final JMenuItem pasteCodebaseItem = new JMenuItem(R("PEPasteCodebaseItem"));
        setButtonMnemonic(pasteCodebaseItem, R("PEPasteCodebaseItemMnemonic"));
        setMenuItemAccelerator(pasteCodebaseItem, R("PEPasteCodebaseItemAccelerator"));
        pasteCodebaseItem.addActionListener(editor.pasteCodebaseButtonAction);
        codebaseMenu.add(pasteCodebaseItem);

        final JMenu viewMenu = new JMenu(R("PEViewMenu"));
        setButtonMnemonic(viewMenu, R("PEViewMenuMnemonic"));

        final JMenuItem customPermissionsItem = new JMenuItem(R("PECustomPermissionsItem"));
        setButtonMnemonic(customPermissionsItem, R("PECustomPermissionsItemMnemonic"));
        setMenuItemAccelerator(customPermissionsItem, R("PECustomPermissionsItemAccelerator"));
        customPermissionsItem.addActionListener(editor.viewCustomButtonAction);

        viewMenu.add(customPermissionsItem);
        menuBar.add(viewMenu);

        final JMenu helpMenu = new JMenu(R("PEHelpMenu"));
        setButtonMnemonic(helpMenu, R("PEHelpMenuMnemonic"));

        final JMenuItem aboutPolicyEditorItem = new JMenuItem(R("PEAboutPolicyEditorItem"));
        setButtonMnemonic(aboutPolicyEditorItem, R("PEAboutPolicyEditorItemMnemonic"));
        aboutPolicyEditorItem.addActionListener(editor.aboutPolicyEditorButtonAction);
        helpMenu.add(aboutPolicyEditorItem);

        final JMenuItem aboutITW = new JMenuItem(R("CPTabAbout"));
        //setButtonMnemonic(aboutPolicyEditorItem, R("PEAboutPolicyEditorItemMnemonic"));
        aboutITW.addActionListener(editor.aboutItwButtonAction);
        helpMenu.add(aboutITW);
        
        final JMenuItem policyEditorHelpItem = new JMenuItem(R("PEPolicyEditorHelpItem"));
        setButtonMnemonic(policyEditorHelpItem, R("PEPolicyEditorHelpItemMnemonic"));
        policyEditorHelpItem.addActionListener(editor.policyEditorHelpButtonAction);
        helpMenu.addSeparator();
        helpMenu.add(policyEditorHelpItem);

        menuBar.add(helpMenu);
        /*
         * JList has default Ctrl-C and Ctrl-V bindings, which we want to override with custom actions
         */
        final InputMap listInputMap = editor.list.getInputMap();
        final ActionMap listActionMap = editor.list.getActionMap();

        final Action listCopyOverrideAction = new AbstractAction() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                editor.copyCodebaseButtonAction.actionPerformed(e);
            }
        };

        final Action listPasteOverrideAction = new AbstractAction() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                editor.pasteCodebaseButtonAction.actionPerformed(e);
            }
        };

        listInputMap.put(copyCodebaseItem.getAccelerator(), "CopyCodebaseOverride");
        listActionMap.put("CopyCodebaseOverride", listCopyOverrideAction);
        listInputMap.put(pasteCodebaseItem.getAccelerator(), "PasteCodebaseOverride");
        listActionMap.put("PasteCodebaseOverride", listPasteOverrideAction);

        return menuBar;
    }

    /**
     * Lay out all controls, tooltips, etc.
     */
    private void setupLayout() {
        final JLabel checkboxLabel = new JLabel();
        checkboxLabel.setText(R("PECheckboxLabel"));
        checkboxLabel.setBorder(new EmptyBorder(2, 2, 2, 2));
        final GridBagConstraints checkboxLabelConstraints = new GridBagConstraints();
        checkboxLabelConstraints.gridx = 2;
        checkboxLabelConstraints.gridy = 0;
        checkboxLabelConstraints.fill = GridBagConstraints.HORIZONTAL;
        add(checkboxLabel, checkboxLabelConstraints);

        final GridBagConstraints checkboxConstraints = new GridBagConstraints();
        checkboxConstraints.anchor = GridBagConstraints.LINE_START;
        checkboxConstraints.fill = GridBagConstraints.HORIZONTAL;
        checkboxConstraints.weightx = 0;
        checkboxConstraints.weighty = 0;
        checkboxConstraints.gridx = 2;
        checkboxConstraints.gridy = 1;

        for (final JCheckBox box : checkboxMap.values()) {
            if (PolicyEditorPermissions.Group.anyContains(box, checkboxMap)) {
                //do not show boxes in any group
                continue;
            }
            add(box, checkboxConstraints);
            checkboxConstraints.gridx++;
            // Two columns of checkboxes
            if (checkboxConstraints.gridx > 3) {
                checkboxConstraints.gridx = 2;
                checkboxConstraints.gridy++;
            }
        }
        //add groups
        for (final PolicyEditorPermissions.Group g : PolicyEditorPermissions.Group.values()) {
            //no metter what, put group title on new line
            checkboxConstraints.gridy++;
            //all groups are in second column
            checkboxConstraints.gridx = 2;
            final JCheckBoxWithGroup groupCh = new JCheckBoxWithGroup(g);
            groupBoxList.add(groupCh);
            final JPanel groupPanel = new JPanel(new GridBagLayout());
            groupPanel.setBorder(new LineBorder(Color.black));
            groupCh.setToolTipText(R("PEGrightClick"));
            groupCh.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(final MouseEvent e) {
                    if (e.getButton() == MouseEvent.BUTTON3) {
                        toggleExpandedCheckboxGroupPanel(groupPanel);
                    }
                }
            });
            groupCh.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(final KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ENTER || e.getKeyCode() == KeyEvent.VK_CONTEXT_MENU) {
                        toggleExpandedCheckboxGroupPanel(groupPanel);
                    }
                }
            });
            groupCh.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(final ActionEvent e) {
                    final String codebase = getSelectedCodebase();
                    if (codebase == null) {
                        return;
                    }
                    List<ActionListener> backup = new LinkedList<>();
                    for (final ActionListener l : groupCh.getActionListeners()) {
                        backup.add(l);
                        groupCh.removeActionListener(l);
                    }
                    for (final PolicyEditorPermissions p : groupCh.getGroup().getPermissions()) {
                        policyEditorController.setPermission(codebase, p, groupCh.isSelected());
                    }
                    setChangesMade(true);
                    updateCheckboxes(codebase);
                    for (final ActionListener al : backup) {
                        groupCh.addActionListener(al);
                    }

                }
            });
            add(groupCh, checkboxConstraints);
            // place panel with members below the title
            checkboxConstraints.gridy++;
            checkboxConstraints.gridx = 2;
            // spread group's panel over two columns
            checkboxConstraints.gridwidth = 2;
            checkboxConstraints.fill = GridBagConstraints.BOTH;
            add(groupPanel, checkboxConstraints);
            final GridBagConstraints groupCheckboxLabelConstraints = new GridBagConstraints();
            groupCheckboxLabelConstraints.anchor = GridBagConstraints.LINE_START;
            groupCheckboxLabelConstraints.weightx = 0;
            groupCheckboxLabelConstraints.weighty = 0;
            groupCheckboxLabelConstraints.gridx = 1;
            groupCheckboxLabelConstraints.gridy = 1;
            for (final PolicyEditorPermissions p : g.getPermissions()) {
                groupPanel.add(checkboxMap.get(p), groupCheckboxLabelConstraints);
                // Two columns of checkboxes
                groupCheckboxLabelConstraints.gridx++;
                if (groupCheckboxLabelConstraints.gridx > 2) {
                    groupCheckboxLabelConstraints.gridx = 1;
                    groupCheckboxLabelConstraints.gridy++;
                }
            }
            groupPanel.setVisible(false);
            //reset
            checkboxConstraints.gridwidth = 1;
        }

        final JLabel codebaseListLabel = new JLabel(R("PECodebaseLabel"));
        codebaseListLabel.setBorder(new EmptyBorder(2, 2, 2, 2));
        final GridBagConstraints listLabelConstraints = new GridBagConstraints();
        listLabelConstraints.fill = GridBagConstraints.HORIZONTAL;
        listLabelConstraints.gridx = 0;
        listLabelConstraints.gridy = 0;
        add(codebaseListLabel, listLabelConstraints);

        list.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) {
                    return; // ignore first click, act on release
                }
                final String codebase = getSelectedCodebase();
                if (codebase == null) {
                    return;
                }
                updateCheckboxes(codebase);
            }
        });
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setViewportView(list);
        final GridBagConstraints listConstraints = new GridBagConstraints();
        listConstraints.fill = GridBagConstraints.BOTH;
        listConstraints.weightx = 1;
        listConstraints.weighty = 1;
        listConstraints.gridheight = checkboxConstraints.gridy + 1;
        listConstraints.gridwidth = 2;
        listConstraints.gridx = 0;
        listConstraints.gridy = 1;
        add(scrollPane, listConstraints);

        final GridBagConstraints addCodebaseButtonConstraints = new GridBagConstraints();
        addCodebaseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;
        addCodebaseButtonConstraints.gridx = 0;
        addCodebaseButtonConstraints.gridy = listConstraints.gridy + listConstraints.gridheight + 1;
        setButtonMnemonic(addCodebaseButton, R("PEAddCodebaseMnemonic"));
        add(addCodebaseButton, addCodebaseButtonConstraints);

        final GridBagConstraints removeCodebaseButtonConstraints = new GridBagConstraints();
        removeCodebaseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;
        removeCodebaseButtonConstraints.gridx = addCodebaseButtonConstraints.gridx + 1;
        removeCodebaseButtonConstraints.gridy = addCodebaseButtonConstraints.gridy;
        setButtonMnemonic(removeCodebaseButton, R("PERemoveCodebaseMnemonic"));
        removeCodebaseButton.setPreferredSize(addCodebaseButton.getPreferredSize());
        add(removeCodebaseButton, removeCodebaseButtonConstraints);

        final GridBagConstraints okButtonConstraints = new GridBagConstraints();
        okButtonConstraints.fill = GridBagConstraints.HORIZONTAL;
        okButtonConstraints.gridx = removeCodebaseButtonConstraints.gridx + 2;
        okButtonConstraints.gridy = removeCodebaseButtonConstraints.gridy;
        add(okButton, okButtonConstraints);

        final GridBagConstraints cancelButtonConstraints = new GridBagConstraints();
        cancelButtonConstraints.fill = GridBagConstraints.HORIZONTAL;
        cancelButtonConstraints.gridx = okButtonConstraints.gridx + 1;
        cancelButtonConstraints.gridy = okButtonConstraints.gridy;
        add(closeButton, cancelButtonConstraints);

        setMinimumSize(getPreferredSize());
    }

    void setChangesMade(final boolean b) {
        policyEditorController.setChangesMade(b);
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                setParentWindowTitle(getWindowTitleForStatus());
            }
        });
    }

    private void resetCodebases() {
        listModel.clear();
        policyEditorController.clearPermissions();
        policyEditorController.clearCustomPermissions();
    }

    /**
     * @return whether this PolicyEditor is currently opening or saving a policy file to disk
     */
    public boolean isPerformingIO() {
        return policyEditorController.performingIO();
    }

    private void openAndParsePolicyFile() {
        resetCodebases();
        try {
            policyEditorController.getFile().createNewFile();
        } catch (final IOException e) {
            OutputController.getLogger().log(e);
        }
        final OpenFileResult ofr = FileUtils.testFilePermissions(policyEditorController.getFile());
        if (ofr == OpenFileResult.FAILURE || ofr == OpenFileResult.NOT_FILE) {
            FileUtils.showCouldNotOpenFilepathDialog(PolicyEditor.this, policyEditorController.getFile().getPath());
            return;
        }
        if (ofr == OpenFileResult.CANT_WRITE) {
            FileUtils.showReadOnlyDialog(PolicyEditor.this);
        }


        final Window parentWindow = SwingUtilities.getWindowAncestor(this);
        final JDialog progressIndicator = new IndeterminateProgressDialog(parentWindow, "Loading...");
        final SwingWorker<Void, Void> openPolicyFileWorker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    if (parentWindow != null) {
                        invokeRunnableOrEnqueueLater(new Runnable() {
                            @Override
                            public void run() {
                                progressIndicator.setLocationRelativeTo(parentWindow);
                                progressIndicator.setVisible(true);
                            }
                        });
                    }
                    policyEditorController.openAndParsePolicyFile();
                } catch (final FileNotFoundException fnfe) {
                    OutputController.getLogger().log(fnfe);
                    FileUtils.showCouldNotOpenDialog(PolicyEditor.this, R("PECouldNotOpen"));
                } catch (final IOException | InvalidPolicyException e) {
                    OutputController.getLogger().log(e);
                    OutputController.getLogger().log(OutputController.Level.ERROR_ALL, R("RCantOpenFile", policyEditorController.getFile().getPath()));
                    FileUtils.showCouldNotOpenDialog(PolicyEditor.this, R("PECouldNotOpen"));
                }
                return null;
            }

            @Override
            public void done() {
                for (final String codebase : policyEditorController.getCodebases()) {
                    final String model;
                    if (codebase.isEmpty()) {
                        model = R("PEGlobalSettings");
                    } else {
                        model = codebase;
                    }
                    if (!listModel.contains(model)) {
                        listModel.addElement(model);
                    }
                }
                addNewCodebase("");
                progressIndicator.setVisible(false);
                progressIndicator.dispose();
                setChangesMade(false);
            }
        };
        openPolicyFileWorker.execute();
    }

    /**
     * Save the policy model into the file pointed to by the filePath field.
     */
    private void savePolicyFile() {
        final int overwriteChanges = checkPolicyChangesWithDialog();
        switch (overwriteChanges) {
            case JOptionPane.YES_OPTION:
                openAndParsePolicyFile();
                return;
            case JOptionPane.NO_OPTION:
                break;
            case JOptionPane.CANCEL_OPTION:
                return;
            default:
                break;
        }

        final Window parentWindow = SwingUtilities.getWindowAncestor(this);
        final JDialog progressIndicator = new IndeterminateProgressDialog(parentWindow, "Saving...");
        final SwingWorker<Void, Void> savePolicyFileWorker = new SwingWorker<Void, Void>() {
            @Override
            public Void doInBackground() throws Exception {
                try {
                    if (parentWindow != null) {
                        invokeRunnableOrEnqueueLater(new Runnable() {
                            @Override
                            public void run() {
                                progressIndicator.setLocationRelativeTo(parentWindow);
                                progressIndicator.setVisible(true);
                            }
                        });
                    }
                    policyEditorController.savePolicyFile();
                } catch (final IOException e) {
                    OutputController.getLogger().log(e);
                    showCouldNotSaveDialog();
                }
                return null;
            }

            @Override
            public void done() {
                showChangesSavedDialog();
                progressIndicator.setVisible(false);
                progressIndicator.dispose();
                setChangesMade(false);
            }
        };
        savePolicyFileWorker.execute();
    }

    /**
     * Show a dialog informing the user that their changes have been saved.
     */
    private void showChangesSavedDialog() {
        // This dialog is often displayed when closing the editor, and so PolicyEditor
        // may already be disposed when this dialog appears. Give a weak reference so
        // that this dialog doesn't prevent the JVM from exiting
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(parentPolicyEditor.get(), R("PEChangesSaved"));
            }
        });
    }

    /**
     * Show a dialog informing the user that their changes could not be saved.
     */
    private void showCouldNotSaveDialog() {
        // This dialog is often displayed when closing the editor, and so PolicyEditor
        // may already be disposed when this dialog appears. Give a weak reference so
        // that this dialog doesn't prevent the JVM from exiting
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(parentPolicyEditor.get(), R("PECouldNotSave"), R("Error"), JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void showClipboardErrorDialog() {
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(parentPolicyEditor.get(), R("PEClipboardError"), R("Error"), JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void showInvalidPolicyExceptionDialog(final String codebase) {
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(parentPolicyEditor.get(), R("PEInvalidPolicy", codebase), R("Error"), JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void showCouldNotAccessClipboardDialog() {
        invokeRunnableOrEnqueueLater(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(parentPolicyEditor.get(), R("PEClipboardAccessError"), R("Error"), JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    /**
     * Detect if the policy settings have changed, either on-disk or in-app.
     * If an on-disk change has occurred, update the Md5.
     * @return The user's choice (Yes/No/Cancel - see JOptionPane constants). 
     * "Cancel" if the file hasn't changed but the user has made modifications
     * to the settings. "No" otherwise
     * @throws IOException if the file cannot be read
     */
    private int checkPolicyChangesWithDialog() {
        boolean changed;
        try {
            changed = policyEditorController.fileHasChanged();
        } catch (FileNotFoundException e) {
            OutputController.getLogger().log(e);
            JOptionPane.showMessageDialog(PolicyEditor.this, R("PEFileMissing"), R("PEFileModified"), JOptionPane.WARNING_MESSAGE);
            return JOptionPane.NO_OPTION;
        } catch (IOException e) {
            OutputController.getLogger().log(e);
            changed = true;
        }
        if (changed) {
            String policyFilePath;
            try {
                policyFilePath = policyEditorController.getFile().getCanonicalPath();
            } catch (final IOException e) {
                OutputController.getLogger().log(e);
                policyFilePath = policyEditorController.getFile().getPath();
            }
            return JOptionPane.showConfirmDialog(PolicyEditor.this, R("PEFileModifiedDetail", policyFilePath,
                    R("PEFileModified"), JOptionPane.YES_NO_CANCEL_OPTION));
        } else if (!policyEditorController.changesMade()) {
            //Return without saving or reloading
            return JOptionPane.CANCEL_OPTION;
        }
        return JOptionPane.NO_OPTION;
    }

    private void toggleExpandedCheckboxGroupPanel(final JPanel groupPanel) {
        groupPanel.setVisible(!groupPanel.isVisible());
        PolicyEditor.this.validate();
        final Window w = SwingUtilities.getWindowAncestor(PolicyEditor.this);
        if (w != null) {
            w.pack();
        }
    }

    /**
     * Start a Policy Editor instance.
     * @param args "-file $FILENAME" and/or "-codebase $CODEBASE" are accepted flag/value pairs.
     * -file specifies a file path to be opened by the editor. If none is provided, the default
     * policy file location for the user is opened.
     * -codebase specifies (a) codebase(s) to start the editor with. If the entry already exists,
     * it will be selected. If it does not exist, it will be created, then selected. Multiple
     * codebases can be used, separated by spaces.
     * -help will print a help message and immediately return (no editor instance opens)
     */
    public static void main(final String[] args) {
        final OptionParser optionParser = new OptionParser(args, OptionsDefinitions.getPolicyEditorOptions());
        
        if (optionParser.hasOption(OptionsDefinitions.OPTIONS.VERBOSE)) {
            JNLPRuntime.setDebug(true);
        }

        if (optionParser.hasOption(OptionsDefinitions.OPTIONS.HELP1)) {
            final TextsProvider helpMessagesProvider = new PolicyEditorTextsProvider("utf-8", new PlainTextFormatter(), true, true);
            String HELP_MESSAGE = "\n";
            if (JNLPRuntime.isDebug()) {
                HELP_MESSAGE = HELP_MESSAGE + helpMessagesProvider.writeToString();
            } else {
                HELP_MESSAGE = HELP_MESSAGE
                        + helpMessagesProvider.prepare().getSynopsis()
                        + helpMessagesProvider.getFormatter().getNewLine()
                        + helpMessagesProvider.prepare().getOptions()
                        + helpMessagesProvider.getFormatter().getNewLine();
            }
            OutputController.getLogger().printOut(HELP_MESSAGE);
            return;
        }

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (final Exception e) {
            // not really important, so just ignore
        }

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                final String filepath = getFilePathArgument(optionParser);
                final PolicyEditorWindow frame = getPolicyEditorFrame(filepath);
                frame.asWindow().setVisible(true);
                final List<String> codebases = optionParser.getParams(OptionsDefinitions.OPTIONS.CODEBASE);
                for (final String url : codebases) {
                    frame.getPolicyEditor().addNewCodebase(url);
                }
            }
        });
    }

    private static String getFilePathArgument(OptionParser optionParser) {
        final boolean openDefaultFile = optionParser.hasOption(OptionsDefinitions.OPTIONS.DEFAULTFILE);
        final boolean hasFileArgument = optionParser.hasOption(OptionsDefinitions.OPTIONS.FILE);
        final boolean hasMainArgument = optionParser.mainArgExists();
        if ((hasFileArgument && openDefaultFile) || (hasMainArgument && openDefaultFile)) {
            throw new IllegalArgumentException(R("PEDefaultFileFilePathSpecifiedError"));
        } else if (hasFileArgument && hasMainArgument) {
            throw new IllegalArgumentException(R("PEMainArgAndFileSwitchSpecifiedError"));
        }

        String filepath = null;
        if (hasFileArgument) {
            filepath = cleanFilePathArgument(optionParser.getParam(OptionsDefinitions.OPTIONS.FILE));
        } else if (hasMainArgument) {
            filepath = cleanFilePathArgument(optionParser.getMainArg());
        } else if (openDefaultFile) {
            try {
                filepath = getDefaultPolicyFilePath();
            } catch (URISyntaxException e) {
                OutputController.getLogger().log(e);
                throw new RuntimeException(e);
            }
        }
        return filepath;
    }

    private static String cleanFilePathArgument(String filepath) {
        if (filepath == null) {
            return null;
        } else if (filepath.isEmpty() || filepath.trim().isEmpty()) {
            return null;
        } else {
            return filepath;
        }
    }

    /**
     * Create a new PolicyEditor instance without passing argv. The returned instance is not
     * yet set visible.
     * @param filepath a policy file to open at start, or null if no file to load
     * @return a reference to a new PolicyEditor instance
     */
    public static PolicyEditor createInstance(final String filepath) {
        return new PolicyEditor(filepath);
    }

}
