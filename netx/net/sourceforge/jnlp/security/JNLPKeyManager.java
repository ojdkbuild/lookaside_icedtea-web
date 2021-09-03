/* JNLPKeyManager
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

package net.sourceforge.jnlp.security;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;

public class JNLPKeyManager implements X509KeyManager {
    private static final Semaphore mutex = new Semaphore(1);
    private static Map<String, String> chosenAliases = new LinkedHashMap<>();
    private static boolean canceledByUser = false;

    private final X509KeyManager km;
    private final String propAlias;

    public JNLPKeyManager(X509KeyManager km, String propAlias) {
        this.km = km;
        this.propAlias = propAlias;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return km.getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        if (null != keyTypes) {
            for (String kt : keyTypes) {
                if (null != kt) {
                    String[] aliases = getClientAliases(kt, issuers);
                    if (null != aliases) {
                        if (null != propAlias && !propAlias.isEmpty()) {
                            for (String alias : aliases) {
                                if (propAlias.equalsIgnoreCase(alias)) {
                                    return alias;
                                }
                            }
                        } else if (aliases.length > 1) {
                            String chosen = getChosenAlias(socket, kt, Arrays.asList(aliases));
                            if (null != chosen) {
                                return chosen;
                            }
                        }
                    }
                }
            }
        }
        return km.chooseClientAlias(keyTypes, issuers, socket);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return km.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return km.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return km.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return km.getPrivateKey(alias);
    }

    private static String getChosenAlias(Socket socket, String keyType, List<String> aliases) {
        try {
            try {
                mutex.acquire();
                if (canceledByUser) {
                    return null;
                }
                String chosenBefore = chosenAliases.get(keyType);
                if (null != chosenBefore) {
                    if (aliases.contains(chosenBefore)) {
                        return chosenBefore;
                    } else {
                        chosenAliases.remove(keyType);
                    }
                }
                String ipAddress = getIpAddress(socket);
                String chosen = SecurityDialogs.showCertAliasListPrompt(ipAddress, keyType, aliases);
                if (null != chosen) {
                    chosenAliases.put(keyType, chosen);
                } else {
                    canceledByUser = true;
                }
                return chosen;
            } finally {
                mutex.release();
            }
        } catch (InterruptedException e) {
            return null;
        }
    }

    private static String getIpAddress(Socket socket) {
        try {
            return socket.getInetAddress().getHostAddress();
        } catch (Exception e) {
            return "N/A";
        }
    }
}
