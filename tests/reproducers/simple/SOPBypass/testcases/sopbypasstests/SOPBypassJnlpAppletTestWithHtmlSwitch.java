/* 
 Copyright (C) 2015 Red Hat, Inc.

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
package sopbypasstests;

import org.junit.Test;
import net.sourceforge.jnlp.annotations.NeedsDisplay;
import net.sourceforge.jnlp.ProcessResult;
import java.util.Collections;

import static sopbypasstests.SOPBypassUtil.*;

public class SOPBypassJnlpAppletTestWithHtmlSwitch extends SOPBypassBeforeAndAfterChunks {

    @Test
    @NeedsDisplay
    public void testLocalAbsoluteArchiveLocalPathCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", server.getUrl("SOPBypass.jar"), server.getUrl("."), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverInstance());
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverInstance());
    }

    @Test
    @NeedsDisplay
    public void testLocalAbsoluteArchiveUnrelatedRemoteCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", server.getUrl("SOPBypass.jar"), serverC.getUrl("."), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverC);
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverInstance());
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverInstance());
    }

    @Test
    @NeedsDisplay
    public void testRemoteAbsoluteArchiveSameRemoteCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", serverC.getUrl("SOPBypass.jar"), serverC.getUrl("."), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverC);
        assertNoDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverC);
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverC);
    }

    @Test
    @NeedsDisplay
    public void testRemoteAbsoluteArchiveUnrelatedRemoteCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", serverB.getUrl("SOPBypass.jar"), serverC.getUrl("."), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverC);
        assertNoDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverB);
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverB);
    }

    @Test
    @NeedsDisplay
    public void testRemoteAbsoluteArchiveLocalPathCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", serverB.getUrl("SOPBypass.jar"), server.getUrl("."), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverB);
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverB);
    }

    @Test
    @NeedsDisplay
    public void testRemoteAbsoluteArchiveLocalDotCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", serverB.getUrl("SOPBypass.jar"), ".", getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverB);
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverB);
    }

    @Test
    @NeedsDisplay
    public void testRemoteAbsoluteArchiveNoCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", serverB.getUrl("SOPBypass.jar"), (String) null, getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverB);
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverB);
    }

    @Test
    @NeedsDisplay
    public void testLocalAbsoluteArchiveNoCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", server.getUrl("SOPBypass.jar"), (String) null, getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverInstance());
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverInstance());
    }

    @Test
    @NeedsDisplay
    public void testLocalRelativeArchiveNoCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", "SOPBypass.jar", (String) null, getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        assertResourcesConnection(pr, serverInstance());
    }

    @Test
    @NeedsDisplay
    public void testLocalRelativeArchiveUnrelatedRemoteCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", "SOPBypass.jar", serverC.getUrl(), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverC);
        assertNoDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        assertResourcesConnection(pr, serverC);
    }

    @Test
    @NeedsDisplay
    public void testLocalAbsoluteArchiveLocalDotCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", server.getUrl("SOPBypass.jar"), ".", getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        //assertResourcesConnection(pr, serverInstance());
        //for some reason, url connection is heving permission denied
        resourcesImpl(false, true, true, pr, serverInstance());

    }

    @Test
    @NeedsDisplay
    public void testLocalRelativeArchiveLocalPathCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", "SOPBypass.jar", server.getUrl("/"), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        assertResourcesConnection(pr, serverInstance());
    }

    @Test
    @NeedsDisplay
    public void testLocalRelativeArchiveLocalDotCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", "SOPBypass.jar", ".", getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverInstance());
        assertDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        assertResourcesConnection(pr, serverInstance());
    }

    @Test
    @NeedsDisplay
    public void testRemoteRelativeArchiveSameRemoteCodebase_JHAT() throws Exception {
        TemplatedHtmlDoc templatedDoc = filterHtml("SOPBypass.html", "SOPBypass", "SOPBypass.jar", serverC.getUrl("/"), getUnrelatedServer());
        ProcessResult pr = performTest(templatedDoc);
        assertCodebaseConnection(pr, serverC);
        assertNoDocumentBaseConnection(pr, serverInstance());
        assertNoUnrelatedConnection(pr, unrelatedInstance());
        assertResourcesConnection(pr, serverC);
    }

    public ProcessResult performTest(TemplatedHtmlDoc templatedDoc) throws Exception {
        ProcessResult pr = server.executeJavawsHeadless(Collections.singletonList("-html"), templatedDoc.getFileName(), getClosingListener(), null, null);
        assertStart(pr);
        assertEnd(pr);
        assertUnprivileged(pr);
        return pr;
    }

}
