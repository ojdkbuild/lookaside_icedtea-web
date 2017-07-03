/*
 Copyright (C) 2012 Red Hat, Inc.

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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import net.sourceforge.jnlp.InformationDesc;
import net.sourceforge.jnlp.JNLPFile;
import net.sourceforge.jnlp.PluginBridgeTest;
import net.sourceforge.jnlp.ServerAccess;
import net.sourceforge.jnlp.annotations.KnownToFail;
import net.sourceforge.jnlp.mock.DummyJNLPFileWithJar;
import net.sourceforge.jnlp.runtime.JNLPRuntime;
import net.sourceforge.jnlp.security.dialogs.AccessWarningPaneComplexReturn;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class XDesktopEntryTest {

    private static final String des1 = "/my/little/Desktop";
    private static final String des2name = "Plocha";
    private static final String des2Res = System.getProperty("user.home") + "/" + des2name;
    private static final String HOME = "HOME";
    private static final String des2 = "$" + HOME + "/" + des2name;
    private static final String des7 = "\"$" + HOME + "/" + des2name + "\"";
    private static final String des7res = System.getProperty("user.home") + "/" + des2name;
    private static final String des8 = "\\\"$" + HOME + "/" + des2name + "\\\"";
    private static final String des8res = "\"" + System.getProperty("user.home") + "/" + des2name + "\"";
    private static final String des9 = "\"$" + HOME + "/\\\"" + des2name + "\\\"\"";
    private static final String des9res = System.getProperty("user.home") + "/\"" + des2name + "\"";
    private static final String src1 = XDesktopEntry.XDG_DESKTOP_DIR + "=" + des1;
    private static final String src2 = "  " + XDesktopEntry.XDG_DESKTOP_DIR + " = " + des1;
    private static final String src3 = "#" + XDesktopEntry.XDG_DESKTOP_DIR + " = " + des1;
    private static final String src4 = XDesktopEntry.XDG_DESKTOP_DIR + "=" + des2;
    private static final String src5 = "  " + XDesktopEntry.XDG_DESKTOP_DIR + " = " + des2;
    private static final String src6 = "#" + XDesktopEntry.XDG_DESKTOP_DIR + " = " + des2;
    private static final String src7 = XDesktopEntry.XDG_DESKTOP_DIR + " = " + des7;
    private static final String src8 = XDesktopEntry.XDG_DESKTOP_DIR + " = " + des8;
    private static final String src9 = XDesktopEntry.XDG_DESKTOP_DIR + " = " + des9;
    private static Map<String, String> backupedEnv;
    private static boolean wasHtml;
    private static boolean wasJavaws;

    @BeforeClass
    public static void saveJnlpRuntimeHtml() {
        wasHtml = JNLPRuntime.isHtml();
        wasJavaws = JNLPRuntime.isWebstartApplication();
    }

    private static void setIsWebstart(boolean value) throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        Field field = JNLPRuntime.class.getDeclaredField("isWebstartApplication");
        field.setAccessible(true);
        field.set(null, value);
    }

    @After
    public void restoreJnlpRuntimeHtml() throws Exception {
        JNLPRuntime.setHtml(wasHtml);
        setIsWebstart(wasJavaws);
    }

    @AfterClass
    public static void restoreJnlpRuntimeHtmlFinally() throws Exception {
        JNLPRuntime.setHtml(wasHtml);
        setIsWebstart(wasJavaws);
    }

    @BeforeClass
    public static void ensureHomeVaribale() throws NoSuchFieldException, IllegalAccessException, IllegalArgumentException, ClassNotFoundException {
        ServerAccess.logOutputReprint("Environment");
        envToString();
        Map<String, String> env = System.getenv();
        if (env.containsKey(HOME)) {
            backupedEnv = null;
        } else {
            backupedEnv = env;
            Map<String, String> m = new HashMap<String, String>(env);
            m.put(HOME, System.getProperty("user.home"));
            fakeEnvironment(m);
            ServerAccess.logOutputReprint("Hacked environment");
            envToString();
        }
    }

    @AfterClass
    public static void restoreHomeVaribale() throws NoSuchFieldException, IllegalAccessException, IllegalArgumentException, ClassNotFoundException {
        Map<String, String> env = System.getenv();
        if (backupedEnv != null) {
            fakeEnvironment(backupedEnv);
            ServerAccess.logOutputReprint("Restored environment");
            envToString();
        }
    }

    private static void fakeEnvironment(Map<String, String> m) throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException, ClassNotFoundException {
        Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
        Field env = processEnvironmentClass.getDeclaredField("theUnmodifiableEnvironment");
        env.setAccessible(true);
        // remove final modifier from field
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(env, env.getModifiers() & ~Modifier.FINAL);
        env.set(null, m);
    }

    @Test
    @KnownToFail
    public void testHomeVariable() {
        Assert.assertTrue("Variable home must be in environment of this run, is not", System.getenv().containsKey(HOME));
        Assert.assertNull("Variable home should be declared  before test run, but was not and so is faked. This should be ok and is thrown just for record. See output of ensureHomeVaribale and restoreHomeVaribale", backupedEnv);
    }

    @Test
    public void getFreedesktopOrgDesktopPathFromtestSimple() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src1)));
        Assert.assertEquals(des1, s);
    }

    @Test
    public void getFreedesktopOrgDesktopPathFromtestSpaced() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src2)));
        Assert.assertEquals(des1, s);
    }

    @Test(expected = IOException.class)
    public void getFreedesktopOrgDesktopPathFromtestCommented() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src3)));
    }

    @Test
    public void getFreedesktopOrgDesktopPathFromtestSimpleWithHome() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src4)));
        Assert.assertEquals(s, des2Res);
    }

    @Test
    public void getFreedesktopOrgDesktopPathFromtestSpacedWithHome() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src5)));
        Assert.assertEquals(s, des2Res);
    }

    @Test
    public void getFreedesktopOrgDesktopPathFromtestSpacedWithHomeAndQuotes() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src7)));
        Assert.assertEquals(s, des7res);
    }

    @Test
    public void getFreedesktopOrgDesktopPathFromtestSpacedWithHomeAndEscapedQuotes() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src8)));
        Assert.assertEquals(s, des8res);
    }

    @Test
    public void getFreedesktopOrgDesktopPathFromtestSpacedWithHomeAndMixedQuotes() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src9)));
        Assert.assertEquals(s, des9res);
    }

    @Test(expected = IOException.class)
    public void getFreedesktopOrgDesktopPathFromtestCommentedWithHome() throws IOException {
        String s = XDesktopEntry.getFreedesktopOrgDesktopPathFrom(new BufferedReader(new StringReader(src6)));
    }

    private static void envToString() {
        mapToString(System.getenv());
    }

    private static void mapToString(Map<String, String> variables) {
        Set<Map.Entry<String, String>> env = variables.entrySet();
        for (Map.Entry<String, String> entry : env) {
            ServerAccess.logOutputReprint(entry.getKey() + " = " + entry.getValue());
        }
    }

    @Test
    public void allFilesHaveSameName() throws IOException {
        JNLPFile jnlpf = new DummyJnlpWithTitle();
        XDesktopEntry xde = new XDesktopEntry(jnlpf);
        File f1 = xde.getShortcutTmpFile();
        File f2 = xde.getLinuxDesktopIconFile();
        File f3 = xde.getLinuxMenuIconFile();
        Assert.assertEquals(f1.getName(), f2.getName());
        Assert.assertEquals(f2.getName(), f3.getName());
    }

    private void testHtmlOccurences(boolean html, boolean javaws, boolean menu, AccessWarningPaneComplexReturn.ShortcutResult.Shortcut type, int occurences) throws Exception {
        JNLPRuntime.setHtml(html);
        setIsWebstart(javaws);
        JNLPFile jnlpf = new DummyJnlpWithTitle();
        XDesktopEntry xde = new XDesktopEntry(jnlpf);
        AccessWarningPaneComplexReturn.ShortcutResult a = new AccessWarningPaneComplexReturn.ShortcutResult(true);
        a.setBrowser("blah");
        a.setFixHref(false);
        a.setShortcutType(type);
        Reader r = xde.getContentsAsReader(menu, a, true);
        String s = FileUtils.getContentOfReader(r);
        Assert.assertEquals(occurences, PluginBridgeTest.countOccurences(s, "-html"));
    }

    @Test
    public void htmlSwitchCorrectAccordingToJnlpRuntimeAndShortcutType() throws Exception {
        AccessWarningPaneComplexReturn.ShortcutResult.Shortcut[] v = AccessWarningPaneComplexReturn.ShortcutResult.Shortcut.values();
        for (AccessWarningPaneComplexReturn.ShortcutResult.Shortcut w : v) {
            int var1 = 0;
            if (w == AccessWarningPaneComplexReturn.ShortcutResult.Shortcut.JAVAWS_HTML) {
                var1 = 1;
            }
            testHtmlOccurences(true, true, true, w, 1);
            testHtmlOccurences(true, false, false, w, var1);
            testHtmlOccurences(true, false, true, w, var1);
            testHtmlOccurences(true, true, false, w, 1);
            testHtmlOccurences(false, true, true, w, 0);
            testHtmlOccurences(false, false, false, w, var1);
            testHtmlOccurences(false, true, false, w, 0);
            testHtmlOccurences(false, false, true, w, var1);
        }
    }

    private static class DummyJnlpWithTitle extends DummyJNLPFileWithJar {

        public DummyJnlpWithTitle() throws MalformedURLException {
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

    };
}
