/*Copyright (C) 2013 Red Hat, Inc.

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

package net.sourceforge.jnlp.security;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import net.sourceforge.jnlp.InformationDesc;
import net.sourceforge.jnlp.LaunchException;
import net.sourceforge.jnlp.browsertesting.browsers.firefox.FirefoxProfilesOperator;
import net.sourceforge.jnlp.config.DeploymentConfiguration;
import net.sourceforge.jnlp.config.PathsAndFiles;
import net.sourceforge.jnlp.mock.DummyJNLPFileWithJar;
import net.sourceforge.jnlp.runtime.JNLPRuntime;
import static net.sourceforge.jnlp.security.SecurityDialogs.AppletAction.*;
import static net.sourceforge.jnlp.security.SecurityDialogs.getIntegerResponseAsAppletAction;
import static net.sourceforge.jnlp.security.SecurityDialogs.getIntegerResponseAsBoolean;
import net.sourceforge.jnlp.security.appletextendedsecurity.AppletSecurityLevel;
import net.sourceforge.jnlp.security.appletextendedsecurity.ExecuteAppletAction;
import net.sourceforge.jnlp.security.appletextendedsecurity.UnsignedAppletTrustConfirmation;
import net.sourceforge.jnlp.security.appletextendedsecurity.impl.UnsignedAppletActionStorageImpl;
import net.sourceforge.jnlp.security.dialogs.apptrustwarningpanel.AppTrustWarningPanel.AppSigningWarningAction;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class SecurityDialogsTest {

    @Test
    public void testGetIntegerResponseAsBoolean() throws Exception {
        Object nullRef = null;
        Object objRef = new Object();
        Float floatRef = 0.0f;
        Double doubleRef = 0.0d;
        Long longRef = (long) 0;
        Byte byteRef = (byte)0;
        Short shortRef = (short)0;
        String strRef = "0";
        Integer intRef1 = 5;
        Integer intRef2 = 0;

        assertFalse("null reference should have resulted in false", getIntegerResponseAsBoolean(nullRef));
        assertFalse("Object reference should have resulted in false", getIntegerResponseAsBoolean(objRef));
        assertFalse("Float reference should have resulted in false", getIntegerResponseAsBoolean(floatRef));
        assertFalse("Double reference should have resulted in false", getIntegerResponseAsBoolean(doubleRef));
        assertFalse("Long reference should have resulted in false", getIntegerResponseAsBoolean(longRef));
        assertFalse("Byte reference should have resulted in false", getIntegerResponseAsBoolean(byteRef));
        assertFalse("Short reference should have resulted in false", getIntegerResponseAsBoolean(shortRef));
        assertFalse("String reference should have resulted in false", getIntegerResponseAsBoolean(strRef));
        assertFalse("Non-0 Integer reference should have resulted in false", getIntegerResponseAsBoolean(intRef1));
        assertTrue("0 Integer reference should have resulted in true", getIntegerResponseAsBoolean(intRef2));
    }

    @Test
    public void testGetIntegerResponseAsAppletAction() throws Exception {
        Object nullRef = null;
        Object objRef = new Object();
        Float floatRef = 0.0f;
        Double doubleRef = 0.0d;
        Long longRef = (long) 0;
        Byte byteRef = (byte) 0;
        Short shortRef = (short) 0;
        String strRef = "0";
        Integer intRef1 = 0;
        Integer intRef2 = 1;
        Integer intRef3 = 2;
        Integer intRef4 = 3;

        assertEquals("null reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(nullRef), CANCEL);
        assertEquals("Object reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(objRef), CANCEL);
        assertEquals("Float reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(floatRef), CANCEL);
        assertEquals("Double reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(doubleRef), CANCEL);
        assertEquals("Long reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(longRef), CANCEL);
        assertEquals("Byte reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(byteRef), CANCEL);
        assertEquals("Short reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(shortRef), CANCEL);
        assertEquals("String reference should have resulted in CANCEL", getIntegerResponseAsAppletAction(strRef), CANCEL);
        assertEquals("Integer reference 0 should have resulted in RUN", getIntegerResponseAsAppletAction(intRef1), RUN);
        assertEquals("Integer reference 1 should have resulted in SANDBOX", getIntegerResponseAsAppletAction(intRef2), SANDBOX);
        assertEquals("Integer reference 2 should have resulted in CANCEL", getIntegerResponseAsAppletAction(intRef3), CANCEL);
        assertEquals("Integer reference 3 should have resulted in CANCEL", getIntegerResponseAsAppletAction(intRef4), CANCEL);
    }

    private static boolean wasHeadless;
    private static boolean wasTrustAll;
    private static boolean wasTrustNone;
    private static String prompt;
    private static URL url;
    private static File appletSecurityBackup;
    private static String seclevel;

    private static class DummyJnlpWithTitleAndUrls extends DummyJNLPFileWithJar {

        public DummyJnlpWithTitleAndUrls() throws MalformedURLException {
            super(new File("/some/path/blah.jar"));
        }

        @Override
        public InformationDesc getInformation() {
            return new InformationDesc(null, false) {

                @Override
                public String getTitle() {
                    return "Demo App";
                }

            };
        }

        @Override
        public URL getCodeBase() {
            return url;
        }

        @Override
        public URL getSourceLocation() {
            return url;
        }

    };

    private static class ExpectedResults {

        public static ExpectedResults PositiveResults = new ExpectedResults(true, RUN, ExecuteAppletAction.YES, null, true);
        public static ExpectedResults NegativeResults = new ExpectedResults(false, CANCEL, ExecuteAppletAction.NO, null, false);
        public final boolean  p1;
        public final SecurityDialogs.AppletAction p2;
        public final ExecuteAppletAction ea;
        public final Object[] np;
        public final boolean b;

        public ExpectedResults(boolean p1, SecurityDialogs.AppletAction p2, ExecuteAppletAction ea,  Object[] np, boolean b) {
            this.p1 = p1;
            this.p2 = p2;
            this.ea = ea;
            this.np = np;
            this.b = b;
        }

    }

    @BeforeClass
    public static void initUrl() throws MalformedURLException {
        url = new URL("http://must.not.be.in/.appletSecurity");
    }

    @BeforeClass
    public static void backupAppletSecurity() throws IOException {
        appletSecurityBackup = File.createTempFile("appletSecurity", "itwTestBAckup");
        FirefoxProfilesOperator.copyFile(PathsAndFiles.APPLET_TRUST_SETTINGS_USER.getFile(), appletSecurityBackup);
    }

    @Before
    public void removeAppletSecurity() throws IOException {
        removeAppletSecurityImpl();
    }

    public static void removeAppletSecurityImpl() throws IOException {
        if (appletSecurityBackup.exists()) {
            PathsAndFiles.APPLET_TRUST_SETTINGS_USER.getFile().delete();
        }
    }

    @AfterClass
    public static void restoreAppletSecurity() throws IOException {
        if (appletSecurityBackup.exists()) {
            removeAppletSecurityImpl();
            FirefoxProfilesOperator.copyFile(appletSecurityBackup, PathsAndFiles.APPLET_TRUST_SETTINGS_USER.getFile());
            appletSecurityBackup.delete();
        }
    }

    @BeforeClass
    public static void saveJnlpRuntime() {
        wasHeadless = JNLPRuntime.isHeadless();
        wasTrustAll = JNLPRuntime.isTrustAll();
        //trutNone is not used in dialogues, its considered as default
        //but is ussed in Unsigned... dialogs family
        wasTrustNone = JNLPRuntime.isTrustNone();
        prompt = JNLPRuntime.getConfiguration().getProperty(DeploymentConfiguration.KEY_SECURITY_PROMPT_USER);
        seclevel = JNLPRuntime.getConfiguration().getProperty(DeploymentConfiguration.KEY_SECURITY_LEVEL);
    }

    @After
    public void restoreJnlpRuntime() throws Exception {
        restoreJnlpRuntimeFinally();
    }

    private static void setPrompt(String p) {
        JNLPRuntime.getConfiguration().setProperty(DeploymentConfiguration.KEY_SECURITY_PROMPT_USER, p);
    }

    private static void setPrompt(boolean p) {
        JNLPRuntime.getConfiguration().setProperty(DeploymentConfiguration.KEY_SECURITY_PROMPT_USER, String.valueOf(p));
    }

    private static void setAS(AppletSecurityLevel as) {
        JNLPRuntime.getConfiguration().setProperty(DeploymentConfiguration.KEY_SECURITY_LEVEL, String.valueOf(as.toChars()));
    }

    @AfterClass
    public static void restoreJnlpRuntimeFinally() throws Exception {
        JNLPRuntime.setHeadless(wasHeadless);
        JNLPRuntime.setTrustAll(wasTrustAll);
        JNLPRuntime.setTrustNone(wasTrustNone);
        setPrompt(prompt);
        JNLPRuntime.getConfiguration().setProperty(DeploymentConfiguration.KEY_SECURITY_LEVEL, seclevel);
    }

    @Test(timeout = 1000)//if gui pops up
    public void testDialogsHeadlessTrustAllPrompt() throws Exception {
        JNLPRuntime.setHeadless(true);
        JNLPRuntime.setTrustAll(true);
        JNLPRuntime.setTrustNone(false); //ignored
        setPrompt(true); //should not metter becasue is headless
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        testAllDialogs(ExpectedResults.PositiveResults);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.DENY_ALL);
        checkUnsignedActing(false, true);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        checkUnsignedActing(false, true);
    }

    @Test(timeout = 1000)//if gui pops up
    public void testDialogsHeadlessTrustNonePrompt() throws Exception {
        JNLPRuntime.setHeadless(true);
        JNLPRuntime.setTrustAll(false);
        JNLPRuntime.setTrustNone(false); //used by Unsigne
        setPrompt(true); //should not metter becasue is headless
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        testAllDialogs(ExpectedResults.NegativeResults);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        checkUnsignedActing(false);
        setAS(AppletSecurityLevel.DENY_ALL);
        checkUnsignedActing(false);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        checkUnsignedActing(false);
    }

    @Test(timeout = 1000)//if gui pops up
    public void testDialogsNotHeadlessTrustAllDontPrompt() throws Exception {
        JNLPRuntime.setHeadless(false); //should not metter as is nto asking
        JNLPRuntime.setTrustAll(true);
        JNLPRuntime.setTrustNone(false); //ignored
        setPrompt(false);
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        testAllDialogs(ExpectedResults.PositiveResults);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.DENY_ALL);
        checkUnsignedActing(false, true);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        checkUnsignedActing(false, true);
    }

    @Test(timeout = 1000)//if gui pops up
    public void testDialogsNotHeadlessTrustNoneDontPrompt() throws Exception {
        JNLPRuntime.setHeadless(false); //should not metter as is nto asking
        JNLPRuntime.setTrustAll(false);
        JNLPRuntime.setTrustNone(false); //ignored
        setPrompt(false);
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        testAllDialogs(ExpectedResults.NegativeResults);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        checkUnsignedActing(false);
        setAS(AppletSecurityLevel.DENY_ALL);
        checkUnsignedActing(false);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        checkUnsignedActing(false);
    }

    private void testAllDialogs(ExpectedResults r) throws MalformedURLException {
        //anything but  shoertcut
        boolean r1 = SecurityDialogs.showAccessWarningDialogB(SecurityDialogs.AccessType.PRINTER, null, null);
        Assert.assertEquals(r.p1, r1);
        //shortcut
        boolean r2 = SecurityDialogs.showAccessWarningDialogB(SecurityDialogs.AccessType.CREATE_DESTKOP_SHORTCUT, null, null);
        Assert.assertEquals(r.p1, r2);
        AppSigningWarningAction r3 = SecurityDialogs.showUnsignedWarningDialog(null);
        Assert.assertEquals(r.ea, r3.getAction());
        SecurityDialogs.AppletAction r4 = SecurityDialogs.showCertWarningDialog(SecurityDialogs.AccessType.UNVERIFIED, null, null, null);
        Assert.assertEquals(r.p2, r4);
        AppSigningWarningAction r5 = SecurityDialogs.showPartiallySignedWarningDialog(null, null, null);
        Assert.assertEquals(r.ea, r5.getAction());
        Object[] r6 = SecurityDialogs.showAuthenicationPrompt(null, 123456, null, null);
        Assert.assertEquals(r.np, r6); //the np is null in both positive and negative
        boolean r7 = SecurityDialogs.showMissingALACAttributePanel(null, null, null);
        Assert.assertEquals(r.b, r7);
        boolean r8 = SecurityDialogs.showMatchingALACAttributePanel(new DummyJnlpWithTitleAndUrls(), url, new HashSet<URL>());
        Assert.assertEquals(r.b, r8);
        boolean r9 = SecurityDialogs.showMissingPermissionsAttributeDialogue(null, null);
        Assert.assertEquals(r.b, r9);
    }

    private void checkUnsignedActing(boolean b) throws MalformedURLException {
        checkUnsignedActing(b, b);
    }

    /*
     *  testPartiallySignedBehaviour(); needs security delegate to set sandbox, so somtetimes results are strange
     */
    private void checkUnsignedActing(boolean b1, boolean b2) throws MalformedURLException {
        boolean r10 = testUnsignedBehaviour();
        Assert.assertEquals(b1, r10);
        boolean r11 = testPartiallySignedBehaviour();
        Assert.assertEquals(b2, r11);
    }

    private boolean testUnsignedBehaviour() throws MalformedURLException {
        try {
            UnsignedAppletTrustConfirmation.checkUnsignedWithUserIfRequired(new DummyJnlpWithTitleAndUrls());
            return true;
        } catch (LaunchException ex) {
            return false;
        }
    }

    private boolean testPartiallySignedBehaviour() throws MalformedURLException {
        try {
            UnsignedAppletTrustConfirmation.checkPartiallySignedWithUserIfRequired(null, new DummyJnlpWithTitleAndUrls(), null);
            return true;
        } catch (LaunchException ex) {
            return false;
        }
    }
    //SPOILER ALERT
    //all test below, are executing gui mode
    //however, they should never popup becasue jnlpruntime should never be initialized in this test
    //so posting to non existing queue leads to  NPE
    //if this logic will ever be  changed, the testswill need fixing
    //msot terrible thing which may happen is, that gui will be really shown
    //then each test must check if it have X, if odnt, pass with message "nothing tested|
    //if it have X, it have to show gui, terminate itself, and then verify that gui was really running

    private void countNPES() throws MalformedURLException {
        int npecounter = 0;
        int metcounter = 0;
        try {
            metcounter++;
            //anything but  shoertcut
            SecurityDialogs.showAccessWarningDialog(SecurityDialogs.AccessType.PRINTER, null, null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            //shortcut
            SecurityDialogs.showAccessWarningDialog(SecurityDialogs.AccessType.CREATE_DESTKOP_SHORTCUT, null, null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            SecurityDialogs.showUnsignedWarningDialog(null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            SecurityDialogs.showCertWarningDialog(SecurityDialogs.AccessType.UNVERIFIED, null, null, null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            AppSigningWarningAction r5 = SecurityDialogs.showPartiallySignedWarningDialog(null, null, null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            SecurityDialogs.showAuthenicationPrompt(null, 123456, null, null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            SecurityDialogs.showMissingALACAttributePanel(null, null, null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            SecurityDialogs.showMatchingALACAttributePanel(new DummyJnlpWithTitleAndUrls(), url, new HashSet<URL>());
        } catch (NullPointerException ex) {
            npecounter++;
        }
        try {
            metcounter++;
            SecurityDialogs.showMissingPermissionsAttributeDialogue(null, null);
        } catch (NullPointerException ex) {
            npecounter++;
        }
        Assert.assertEquals(metcounter, npecounter);
    }

    private void checkUnsignedNPE(boolean b) throws MalformedURLException {
        checkUnsignedNPE(b, b);
    }

    /*
     testPartiallySignedBehaviour(); needs security delegate to set sandbox, so somtetimes results are strange
     */
    private void checkUnsignedNPE(boolean b1, boolean b2) throws MalformedURLException {
        int metcounter = 0;
        boolean ex1 = false;
        boolean ex2 = false;
        try {
            metcounter++;
            testPartiallySignedBehaviour();
        } catch (NullPointerException ex) {
            ex1 = true;
        }
        try {
            metcounter++;
            testUnsignedBehaviour();
        } catch (NullPointerException ex) {
            ex2 = true;
        }
        Assert.assertEquals(2, metcounter);
        Assert.assertEquals(b1, ex1);
        Assert.assertEquals(b2, ex2);
    }

    @Test
    public void testDialogsNotHeadlessTrustNonePrompt() throws Exception {
        JNLPRuntime.setHeadless(false);
        JNLPRuntime.setTrustAll(false);//should notmetter
        JNLPRuntime.setTrustNone(false); //ignored
        setPrompt(true);
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        countNPES();
        checkUnsignedNPE(false);
    }

    @Test
    public void testNormaDialogsNotHeadlessTrustAllPrompt() throws Exception {
        JNLPRuntime.setHeadless(false);
        JNLPRuntime.setTrustAll(true);
        JNLPRuntime.setTrustNone(false);
        setPrompt(true);
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        countNPES();
    }

    @Test
    public void testUnsignedDialogsNotHeadlessTrustAllPrompt() throws Exception {
        JNLPRuntime.setHeadless(false);
        JNLPRuntime.setTrustAll(true);
        JNLPRuntime.setTrustNone(false);
        setPrompt(true); //ignored
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.DENY_ALL);
        checkUnsignedActing(false, true);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        checkUnsignedActing(false, true);
    }

    @Test
    public void testUnsignedDialogsNotHeadlessTrustNonePrompt() throws Exception {
        JNLPRuntime.setHeadless(false);
        JNLPRuntime.setTrustAll(false);
        JNLPRuntime.setTrustNone(true);
        setPrompt(true); //ignored
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        boolean r10 = testUnsignedBehaviour();
        Assert.assertEquals(false, r10);
        checkUnsignedNPE(true, false);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        boolean r11 = testUnsignedBehaviour();
        Assert.assertEquals(false, r11);
        checkUnsignedNPE(true, false);
        setAS(AppletSecurityLevel.DENY_ALL);
        boolean r12 = testUnsignedBehaviour();
        Assert.assertEquals(false, r12);
        checkUnsignedNPE(true, false);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        boolean r13 = testUnsignedBehaviour();
        Assert.assertEquals(false, r13);
        checkUnsignedNPE(true, false);
    }

    @Test
    public void testUnsignedDialogsNotHeadlessTrustNoneTrustAllPrompt() throws Exception {
        JNLPRuntime.setHeadless(false);
        JNLPRuntime.setTrustAll(true);
        JNLPRuntime.setTrustNone(true);
        setPrompt(true); //ignored
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        boolean a = testUnsignedBehaviour();
        Assert.assertFalse(a);
        checkUnsignedNPE(true, false);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        boolean r10 = testUnsignedBehaviour();
        Assert.assertEquals(false, r10);
        checkUnsignedNPE(true, false);
        setAS(AppletSecurityLevel.DENY_ALL);
        boolean r11 = testUnsignedBehaviour();
        Assert.assertEquals(false, r11);
        checkUnsignedNPE(true, false);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        boolean r12 = testUnsignedBehaviour();
        Assert.assertEquals(false, r12);
        checkUnsignedNPE(true, false);
    }
    
    
      @Test
    public void testUnsignedDialogsNotHeadlessPrompt() throws Exception {
        JNLPRuntime.setHeadless(false);
        JNLPRuntime.setTrustAll(false);
        JNLPRuntime.setTrustNone(false);
        setPrompt(true); //ignored
        setAS(AppletSecurityLevel.ALLOW_UNSIGNED);
        checkUnsignedActing(true);
        setAS(AppletSecurityLevel.ASK_UNSIGNED);
        checkUnsignedNPE(true, true);
        setAS(AppletSecurityLevel.DENY_ALL);
        boolean r11 = testUnsignedBehaviour();
        Assert.assertEquals(false, r11);
        checkUnsignedNPE(true, false);
        setAS(AppletSecurityLevel.DENY_UNSIGNED);
        boolean r12 = testUnsignedBehaviour();
        Assert.assertEquals(false, r12);
        checkUnsignedNPE(true, false);
    }

}
