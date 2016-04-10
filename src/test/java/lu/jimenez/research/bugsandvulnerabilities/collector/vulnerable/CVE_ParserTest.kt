package lu.jimenez.research.bugsandvulnerabilities.collector.vulnerable

import lu.jimenez.research.bugsandvulnerabilities.collector.DataCollector
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.shouldEqual
import org.junit.Assert.*

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

class CVE_ParserTest: Spek(){
    init {
        DataCollector.loadingProperties()

        given("a year : 2003") {
            val year = 2003
            on("CVE Analysis") {
                val analysis = CVE_Parser(year)
                analysis.XMLparse()
                it("should return a list of size 0")
                {
                    shouldEqual(0, analysis.list.size)
                }
            }
        }
        given("a year : 2005") {
            val year = 2005

            on("CVE Analysis") {
                val analysis = CVE_Parser(year)
                analysis.XMLparse()
                it("should return a list of size 7")
                {
                    shouldEqual(7, analysis.list.size)
                }
            }
        }

    }
}