/////////////////////////////////////////////////////////////////////////////////////////
//                 University of Luxembourg  -
//                 Interdisciplinary center for Security and Trust (SnT)
//                 Copyright © 2016 University of Luxembourg, SnT
//
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 3 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
//
//
//    Author: Matthieu Jimenez – SnT – matthieu.jimenez@uni.lu
//
//////////////////////////////////////////////////////////////////////////////////////////
package lu.jimenez.research.bugsandvulnerabilities.collector.utils



object Constants {
    //general spec
    var NB_THREAD :Int = 1

    var SOFTWARE = "*"

    //CVE XML
    var YEAR_BEGINNING = 2002
    var YEAR_END = 2016

    //Software to look for
    var SOFTWARE_GIT = "*"
    var BUG_TRACKER = "*"

    var JYTHON= "*"
    var FILE_EXTENSION = "*"

    val DEFAULT_BUG_INDICATORS = listOf(
            //"error",
            "bug"
            //"fix",
           // "issue",
            //"mistake",
            //"incorrect",
           // "fault",
           // "defect",
           // "flaw"
    )
    var BUG_SHARE = 1
    var CLEAR_SHARE: Int = 1
    var CVE_ONLY: Boolean = true
    var REALISTIC_GEN: Boolean = false
    var EXPERIMENTAL_GEN: Boolean = false
}