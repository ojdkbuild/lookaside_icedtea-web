package net.sourceforge.jnlp.util.ui;

import net.sourceforge.jnlp.runtime.JNLPRuntime;

import javax.swing.*;

public class SwingUtils {

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
}
