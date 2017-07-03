/*   Copyright (C) 2013 Red Hat, Inc.

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

package net.sourceforge.jnlp.security.appletextendedsecurity;

import java.net.MalformedURLException;
import static net.sourceforge.jnlp.runtime.Translator.R;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import net.sourceforge.jnlp.JARDesc;
import net.sourceforge.jnlp.JNLPFile;
import net.sourceforge.jnlp.LaunchException;
import net.sourceforge.jnlp.PluginBridge;
import net.sourceforge.jnlp.runtime.JNLPRuntime;
import net.sourceforge.jnlp.runtime.JNLPClassLoader.SecurityDelegate;
import net.sourceforge.jnlp.security.dialogs.apptrustwarningpanel.AppTrustWarningPanel.AppSigningWarningAction;
import net.sourceforge.jnlp.security.CertVerifier;
import net.sourceforge.jnlp.security.SecurityDialogs;
import net.sourceforge.jnlp.util.UrlUtils;
import net.sourceforge.jnlp.util.logging.OutputController;

public class UnsignedAppletTrustConfirmation {

    private static final AppletStartupSecuritySettings securitySettings = AppletStartupSecuritySettings.getInstance();

    private static boolean unsignedConfirmationIsRequired() {
        // If we are using the 'high' security setting or higher, we must confirm
        // if the user wishes to run unsigned applets (not applicable to JNLP-launched apps)
        return !(AppletSecurityLevel.ALLOW_UNSIGNED == securitySettings.getSecurityLevel());
    }

    private static boolean unsignedAppletsAreForbidden() {
        // If we are using the 'very high' security setting or higher, we do not
        // run unsigned applets
        return AppletSecurityLevel.DENY_UNSIGNED == securitySettings.getSecurityLevel()
                || AppletSecurityLevel.DENY_ALL == securitySettings.getSecurityLevel();
    }

    /**
     * Gets the remembered decision, first checking the user policy for an ALWAYS/NEVER,
     * and then the global policy.
     * 
     * @param file the plugin file
     * @param id of wonted  action
     * @return the remembered decision
     */
    public static UnsignedAppletActionEntry getStoredEntry(JNLPFile file, int id) {
        UnsignedAppletActionStorage userActionStorage = securitySettings.getUnsignedAppletActionCustomStorage();
        UnsignedAppletActionStorage globalActionStorage = securitySettings.getUnsignedAppletActionGlobalStorage();

        UnsignedAppletActionEntry globalEntry = getMatchingItem(globalActionStorage, file, id);
        UnsignedAppletActionEntry userEntry = getMatchingItem(userActionStorage, file, id);

        ExecuteAppletAction globalAction = globalEntry == null ? null : globalEntry.getAppletSecurityActions().getAction(id);
        ExecuteAppletAction userAction = userEntry == null ? null : userEntry.getAppletSecurityActions().getAction(id);

        if (userAction == ExecuteAppletAction.ALWAYS || userAction == ExecuteAppletAction.NEVER) {
            return userEntry;
        } else if (globalAction == ExecuteAppletAction.ALWAYS || globalAction == ExecuteAppletAction.NEVER) {
            return globalEntry;
        } else {
            return userEntry;
        }
    }
    public static ExecuteAppletAction getStoredAction(JNLPFile file, int id) {
        UnsignedAppletActionEntry x = getStoredEntry(file, id);
        if (x != null) {
            return x.getAppletSecurityActions().getAction(id);
        }
        return null;
    }

    private static UnsignedAppletActionEntry getMatchingItem(UnsignedAppletActionStorage actionStorage, JNLPFile file, int id) {
        return actionStorage.getMatchingItem(
                UrlUtils.normalizeUrlAndStripParams(file.getSourceLocation(), true /* encode local files */).toString(), 
                UrlUtils.normalizeUrlAndStripParams(file.getCodeBase(), true /* encode local files */).toString(), 
                toRelativePaths(getJars(file), file.getCodeBase().toString()), id);
    }

    /* Extract the archives as relative paths */
    static List<String> toRelativePaths(List<String> paths, String rootPath) {
        List<String> fileNames = new ArrayList<>();
        for (String path : paths) {
            if (path.startsWith(rootPath)) {
                fileNames.add(path.substring(rootPath.length()));
            } else {
                fileNames.add(path);
            }
        }
        return fileNames;
    }

    public static void updateAppletAction(JNLPFile file, ExecuteAppletAction behaviour, boolean rememberForCodeBase, int id) {
        UnsignedAppletActionStorage userActionStorage = securitySettings.getUnsignedAppletActionCustomStorage();

        userActionStorage.lock(); // We should ensure this operation is atomic
        try {
            UnsignedAppletActionEntry oldEntry = getMatchingItem(userActionStorage, file, id);

            URL codebase = UrlUtils.normalizeUrlAndStripParams(file.getCodeBase(), true /* encode local files */);
            URL documentbase = UrlUtils.normalizeUrlAndStripParams(file.getSourceLocation(), true /* encode local files */);

            /* Else, create a new entry */
            UrlRegEx codebaseRegex = UrlRegEx.quote(codebase.toExternalForm());
            UrlRegEx documentbaseRegex = UrlRegEx.quoteAndStar(stripFile(documentbase)); // Match any from codebase and sourceFile "base"
            List<String> archiveMatches = null; // Match any from codebase

            if (!rememberForCodeBase) { 
                documentbaseRegex = UrlRegEx.quote(documentbase.toExternalForm()); // Match only this applet
                archiveMatches = toRelativePaths(getJars(file), file.getCodeBase().toString()); // Match only this applet
            }
            
            /* Update, if entry exists */
            if (oldEntry != null) {
                oldEntry.getAppletSecurityActions().setAction(id, behaviour);
                oldEntry.setTimeStamp(new Date());
                oldEntry.setDocumentBase(documentbaseRegex);
                oldEntry.setCodeBase(codebaseRegex);
                oldEntry.setArchives(archiveMatches);
                userActionStorage.update(oldEntry);
                return;
            }

            UnsignedAppletActionEntry entry = new UnsignedAppletActionEntry(
                    AppletSecurityActions.fromAction(id, behaviour), 
                    new Date(),
                    documentbaseRegex, 
                    codebaseRegex,
                    archiveMatches
            );

            userActionStorage.add(entry);
        } finally {
            userActionStorage.unlock();
        }
    }

    private static List<String> getJars(JNLPFile file) {
        if (file instanceof PluginBridge)
            return ((PluginBridge) file).getArchiveJars();

        List<JARDesc> jars = Arrays.asList(file.getResources().getJARs());
        List<String> result = new ArrayList<String>();
        for (JARDesc jar : jars) {
            result.add(jar.getLocation().toString());
        }
        return result;
    }

    public static void checkUnsignedWithUserIfRequired(JNLPFile file) throws LaunchException {

        if (unsignedAppletsAreForbidden() || JNLPRuntime.isTrustNone()) {
            OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Not running unsigned applet at " + file.getCodeBase() +" because unsigned applets are disallowed by security policy.");
            throw new LaunchException(file, null, R("LSFatal"), R("LCClient"), R("LUnsignedApplet"), R("LUnsignedAppletPolicyDenied"));
        }

        if (!unsignedConfirmationIsRequired() || JNLPRuntime.isTrustAll()) {
            OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Running unsigned applet at " + file.getCodeBase() +" does not require confirmation according to security policy.");
            return;
        }

        ExecuteAppletAction storedAction = getStoredAction(file, AppletSecurityActions.UNSIGNED_APPLET_ACTION);
        OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Stored action for unsigned applet at " + file.getCodeBase() +" was " + storedAction);

        boolean appletOK;

        if (storedAction == ExecuteAppletAction.ALWAYS) {
            appletOK = true;
        } else if (storedAction == ExecuteAppletAction.NEVER) {
            appletOK = false;
        } else {
            // No remembered decision, prompt the user
            AppSigningWarningAction warningResponse = SecurityDialogs.showUnsignedWarningDialog(file);
            ExecuteAppletAction executeAction = warningResponse.getAction();

            appletOK = (executeAction == ExecuteAppletAction.YES || executeAction == ExecuteAppletAction.ALWAYS);

            if (executeAction != null) {
                updateAppletAction(file, executeAction, warningResponse.rememberForCodeBase(), AppletSecurityActions.UNSIGNED_APPLET_ACTION);
            }

            OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Decided action for unsigned applet at " + file.getCodeBase() +" was " + executeAction);
        }

        if (!appletOK) {
            throw new LaunchException(file, null, R("LSFatal"), R("LCClient"), R("LUnsignedApplet"), R("LUnsignedAppletUserDenied"));
        }

    }

    public static void checkPartiallySignedWithUserIfRequired(SecurityDelegate securityDelegate, JNLPFile file,
            CertVerifier certVerifier) throws LaunchException {

        if (JNLPRuntime.isTrustNone()) {
            OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Running partially signed applet at " + file.getCodeBase() + " with only Sandbox permissions due to -Xtrustnone flag");
            securityDelegate.setRunInSandbox();
            return;
        }
        if (JNLPRuntime.isTrustAll()) {
            OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Running partially signed applet at " + file.getCodeBase() + " due to -Xtrustall flag");
            return;
        }

        if (!unsignedConfirmationIsRequired()) {
            OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Running partially signed applet at " + file.getCodeBase() + " does not require confirmation according to security policy.");
            return;
        }

        ExecuteAppletAction storedAction = getStoredAction(file, AppletSecurityActions.UNSIGNED_APPLET_ACTION);
        OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Stored action for partially signed applet at " + file.getCodeBase() + " was " + storedAction);

        boolean appletOK;

        if (storedAction == ExecuteAppletAction.ALWAYS) {
            appletOK = true;
        } else if (storedAction == ExecuteAppletAction.NEVER) {
            appletOK = false;
        } else {
            // No remembered decision, prompt the user
            AppSigningWarningAction warningResponse = SecurityDialogs.showPartiallySignedWarningDialog(file, certVerifier, securityDelegate);
            ExecuteAppletAction executeAction = warningResponse.getAction();

            if (executeAction == ExecuteAppletAction.SANDBOX) {
                securityDelegate.setRunInSandbox();
            }

            appletOK = (executeAction == ExecuteAppletAction.YES || executeAction == ExecuteAppletAction.ALWAYS
                    || executeAction == ExecuteAppletAction.SANDBOX);

            if (executeAction != null) {
                updateAppletAction(file, executeAction, warningResponse.rememberForCodeBase(),AppletSecurityActions.UNSIGNED_APPLET_ACTION);
            }

            OutputController.getLogger().log(OutputController.Level.ERROR_DEBUG, "Decided action for unsigned applet at " + file.getCodeBase() + " was " + executeAction);
        }

        if (!appletOK) {
            throw new LaunchException(file, null, R("LSFatal"), R("LCClient"), R("LPartiallySignedApplet"), R("LPartiallySignedAppletUserDenied"));
        }

    }

    static String stripFile(URL documentbase) {
        //whenused in generation of regec, the trailing slash is very important
        //see the result between http:/some.url/path.* and http:/some.url/path/.*
        return ensureSlashTail(stripFileImp(documentbase));
    }
    
    private static String stripFileImp(URL documentbase) {
        try {
            String normalized = UrlUtils.normalizeUrlAndStripParams(documentbase).toExternalForm().trim();
            if (normalized.endsWith("/") || normalized.endsWith("\\")) {
                return normalized;
            }
            URL middleway = new URL(normalized);
            String file = middleway.getFile();
            int i = Math.max(file.lastIndexOf('/'), file.lastIndexOf('\\'));
            if (i<0){
                return normalized;
            }
            String parent = file.substring(0, i+1);
            String stripped = normalized.replace(file, parent);
            return stripped;
        } catch (Exception ex) {
            OutputController.getLogger().log(ex);
            return documentbase.toExternalForm();
        }

    }

    private static String ensureSlashTail(String s) {
        if (s.endsWith("/")) {
            return s;
        }
        if (s.endsWith("\\")) {
            return s;
        }
        if (s.contains("/")) {
            return s + "/";
        }
        if (s.contains("\\")) {
            return s + "\\";
        }
        return s + "/";
    }

}
