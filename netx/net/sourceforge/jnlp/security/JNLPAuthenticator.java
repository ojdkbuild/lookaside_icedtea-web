/* JNLPAuthenticator
   Copyright (C) 2008  Red Hat

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

package net.sourceforge.jnlp.security;

import java.awt.*;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;

import net.sourceforge.jnlp.security.dialogresults.NamePassword;

import static java.lang.Boolean.parseBoolean;
import static net.sourceforge.jnlp.config.DeploymentConfiguration.KEY_RH_AUTH_DIALOG_MODALITY_CHECK;
import static net.sourceforge.jnlp.runtime.JNLPRuntime.getConfiguration;
import static net.sourceforge.jnlp.security.SecurityDialogs.AuthRequestAttempt.FIRST_TIME;
import static net.sourceforge.jnlp.security.SecurityDialogs.AuthRequestAttempt.REPEATED;
import static net.sourceforge.jnlp.util.logging.OutputController.Level.ERROR_DEBUG;
import static net.sourceforge.jnlp.util.logging.OutputController.Level.MESSAGE_ALL;
import static net.sourceforge.jnlp.util.logging.OutputController.getLogger;

public class JNLPAuthenticator extends Authenticator {
    private final Semaphore mutex = new Semaphore(1);
    private final AuthState state = new AuthState();

    @Override
    public PasswordAuthentication getPasswordAuthentication() {

        final NamePassword response;
        try {
            try {
                mutex.acquire();
                getLogger().log(MESSAGE_ALL, "Password authentication requested");
                if (state.isCanceledByUser()) {
                    throw new RuntimeException("Authentication canceled by user");
                }
                NamePassword hostCreds = state.getHostCredentials(getRequestingHost());
                if (null == hostCreds) {
                    getLogger().log(MESSAGE_ALL, "No cached credentials found, displaying 'first time' auth dialog");
                    response = showAuthDialog(hostCreds, FIRST_TIME);
                    if (null == response) {
                        state.markAsCanceledByUser();
                    }
                    state.putHostCredentials(getRequestingHost(), response);
                } else if (state.equalsThreadURL(getRequestingURL())) {
                    if (state.sameThreadAndHostCredentials(getRequestingHost())) {
                        getLogger().log(MESSAGE_ALL, "Credentials rejected, displaying 'repeated' auth dialog");
                        response = showAuthDialog(hostCreds, REPEATED);
                        if (null == response) {
                            state.markAsCanceledByUser();
                        }
                        state.putHostCredentials(getRequestingHost(), response);
                    } else {
                        response = hostCreds;
                        state.setThreadCreds(hostCreds);
                    }
                } else {
                    response = hostCreds;
                }
                state.setThreadURL(getRequestingURL());
            } finally {
                mutex.release();
            }
        } catch (InterruptedException e) {
            return null;
        }

        if (response == null) {
            return null;
        } else {
            return new PasswordAuthentication(response.getName(), response.getPassword());
        }
    }

    private NamePassword showAuthDialog(NamePassword hostCreds, SecurityDialogs.AuthRequestAttempt attempt) {
        // No security check is required here, because the only way to set
        // parameters for which auth info is needed
        // (Authenticator:requestPasswordAuthentication()), has a security check

        boolean modCheckEnabled = parseBoolean(getConfiguration().getProperty(KEY_RH_AUTH_DIALOG_MODALITY_CHECK));
        if (modCheckEnabled && isModalDialogActive()) {
            // cannot show auth dialog when another dialog is modal
            // assume that startup is canceled in this case
            return null;
        }

        final String username;
        if (null == hostCreds) {
            username = "";
        } else {
            username = String.valueOf(hostCreds.getName());
        }

        SecurityDialogs.AuthUIContext ctx = new SecurityDialogs.AuthUIContext(username, getRequestingHost(),
                getRequestingURL(), getRequestingPrompt(), getRequestorType(), attempt);

        return SecurityDialogs.showAuthenicationPrompt(ctx);
    }

    private static boolean isModalDialogActive() {
        try {
            Window[] windows = Window.getWindows();
            if (null != windows) {
                for (Window w : windows) {
                    if (null != w && w.isShowing() && w instanceof Dialog && ((Dialog) w).isModal()) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            getLogger().log(ERROR_DEBUG, e);
        }
        return false;
    }

    private static class AuthState {
        private final Map<String, NamePassword> hostCreds = new LinkedHashMap<>();
        private final ThreadLocal<String> threadURL = new ThreadLocal<>();
        private final ThreadLocal<NamePassword> threadCreds = new ThreadLocal<>();
        private boolean canceledByUser = false;

        NamePassword getHostCredentials(String hostname) {
            String key = String.valueOf(hostname);
            return hostCreds.get(key);
        }

        void putHostCredentials(String hostname, NamePassword creds) {
            String key = String.valueOf(hostname);
            hostCreds.put(key, creds);
            threadCreds.set(creds);
        }

        boolean equalsThreadURL(URL url) {
            String reqUrl = String.valueOf(url);
            String prevUrl = threadURL.get();
            return reqUrl.equals(prevUrl);
        }

        void setThreadURL(URL url) {
            String st = String.valueOf(url);
            threadURL.set(st);
        }

        boolean sameThreadAndHostCredentials(String hostname) {
            String key = String.valueOf(hostname);
            NamePassword hc = hostCreds.get(key);
            NamePassword tc = threadCreds.get();
            if (null == hc || null == hc.getName() || null == hc.getPassword() ||
                    null == tc || null == tc.getName() || null == tc.getPassword()) {
                return false;
            }
            return hc.getName().equals(tc.getName()) &&
                    Arrays.equals(hc.getPassword(), tc.getPassword());
        }

        void setThreadCreds(NamePassword creds) {
            threadCreds.set(creds);
        }

        public boolean isCanceledByUser() {
            return canceledByUser;
        }

        void markAsCanceledByUser() {
            canceledByUser = true;
        }

    }

}
