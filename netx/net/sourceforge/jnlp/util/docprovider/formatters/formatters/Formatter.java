/* 
   Copyright (C) 2014 Red Hat, Inc.

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

package net.sourceforge.jnlp.util.docprovider.formatters.formatters;

public interface Formatter {

    public String process(String s);

    public String wrapParagraph(String s);

    public String getHeaders(String id, String encoding);

    public String getNewLine();
    
    public String getNewLine(int count);
    
    public String getBold(String s);

    public String getBoldOpening();

    public String getBoldClosing();
    
    public String getBreakAndBold();
    
    public String getCloseBoldAndBreak();
    
    public String getBoldCloseNwlineBoldOpen();

    public String getTitle(String name);

    public String getUrl(String url);

    public String getUrl(String url, String  appearence);
    
    public String getOption(String key, String  value);

    public String getSeeAlso(String s);

    public String getTail();

    public String getFileSuffix();
    
    public String getAdressLink(String s);
    
    public String replaceLtGtCharacters(String s);

}
