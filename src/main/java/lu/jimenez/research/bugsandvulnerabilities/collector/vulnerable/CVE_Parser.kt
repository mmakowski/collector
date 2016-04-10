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
package lu.jimenez.research.bugsandvulnerabilities.collector.vulnerable

import lu.jimenez.research.bugsandvulnerabilities.collector.constants.Constants
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.net.URL
import java.util.*
import java.util.regex.Matcher
import java.util.regex.Pattern
import javax.xml.namespace.QName
import javax.xml.stream.XMLInputFactory
import javax.xml.stream.XMLStreamException
import javax.xml.stream.events.XMLEvent




/**
 * CVE_Parser Class
 *
 * Class to parse the vulnerability NVD Files, to change the software under consideration change constant SOFTWARE
 *
 * @constructor create a parser for the given year
 * @param year
 *
 * Use of [Constants].SOFTWARE and [Constants].SOFTWARE_GIT
 */
class CVE_Parser(year: Int) {

    private val fileToParse: URL
    val list: MutableList<String>


    init {
        fileToParse = javaClass.classLoader.getResource("cve_XML/nvdcve-2.0-$year.xml")
        this.list = ArrayList<String>()
    }


    /**************************************************************
     * XML Parsing                                                *
     */

    /**
     * Method to parse the XML NVD file and return a list of all CVE-CWE  for a given software that have a commit link
     */
    fun XMLparse(): CVE_Parser {
        try {
            val factory = XMLInputFactory.newInstance()
            val eventReader = factory.createXMLEventReader(
                    FileInputStream(fileToParse.path))
            factory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, false)
            var cve = ""
            var cw = ""
            var linux = false
            while (eventReader.hasNext()) {
                var xmlEvent = eventReader.nextEvent()
                if (xmlEvent.isStartElement) {
                    var startElement = xmlEvent.asStartElement()

                    when (startElement.name.localPart) {

                        "entry" -> {
                            linux = false
                            val idAttr = startElement.getAttributeByName(QName("id"))
                            cw = ""
                            cve = idAttr?.value ?: cve
                        }
                        "vulnerable-configuration" -> {
                            xmlEvent = eventReader.nextEvent()
                            while (functionSOft(xmlEvent)) {
                                if (xmlEvent.isStartElement) {
                                    val tt = xmlEvent.asStartElement().getAttributeByName(QName("name"))
                                    if (tt != null) {
                                        val ttt = tt.value
                                        val m = softwareMatch(ttt)
                                        if (m.find()) {
                                            val soft = m.group(1)
                                            if (soft.compareTo(Constants.SOFTWARE) == 0) linux = true
                                        }
                                    }
                                }
                                xmlEvent = eventReader.nextEvent()
                            }
                        }
                        "vulnerable-software-list" -> {
                            xmlEvent = eventReader.nextEvent()
                            while (functionSOft(xmlEvent)) {
                                if (!xmlEvent.isStartElement && !xmlEvent.isEndElement) {
                                    val m = softwareMatch(xmlEvent.asCharacters().data)
                                    if (m.find()) {
                                        val soft = m.group(1)
                                        if (soft.compareTo(Constants.SOFTWARE) == 0) linux = true
                                    }
                                }
                                xmlEvent = eventReader.nextEvent()
                            }
                        }
                        "cwe" -> {
                            val idAttr = startElement.getAttributeByName(QName("id"))
                            cw = idAttr?.value ?: cw
                        }
                        "references" -> {
                            //startElement = xmlEvent.asStartElement();
                            eventReader.nextEvent()
                            eventReader.nextEvent()
                            eventReader.nextEvent()
                            eventReader.nextEvent()
                            eventReader.nextEvent()
                            xmlEvent = eventReader.nextEvent()
                            startElement = xmlEvent.asStartElement()
                            val idAttr = startElement.getAttributeByName(QName("href"))
                            if (idAttr != null) {
                                var lin = idAttr.value
                                val m = urlMatch(lin)
                                val cvecwe: String
                                if (m.find() && linux) {
                                    if (cw != "") {
                                        cvecwe = cw + "_" + cve
                                    } else
                                        cvecwe = "CWE-0_" + cve
                                    lin = cvecwe + " : " + m.group(4)
                                    this.list.add(lin)
                                }
                            }
                        }
                        else -> eventReader.nextEvent()
                    }
                }
            }
        } catch(e: FileNotFoundException) {
            e.printStackTrace()
        } catch(e: XMLStreamException) {
            e.printStackTrace()
        }
        return this
    }

    /**
     * Sub Method
     *
     * @param xmlEvent xml event under consideration
     * @return true if the xml event is different from vulnerable-Software-list
     */
    private fun functionSOft(xmlEvent: XMLEvent): Boolean {
        return !xmlEvent.isEndElement || xmlEvent.asEndElement().name.localPart != "vulnerable-software-list"
    }


    /**************************************************************
     * MATCHER                                                    *
     */


    /**
     * Method to create a Matcher for finding a given software in a NVD software label
     * @param soft: software under study
     * *
     * @return Matcher for the software
     */
    private fun softwareMatch(soft: String): Matcher {
        val re1 = ".*?"    // Non-greedy match on filler
        val re2 = "(?:[a-z][a-z]+)"    // Uninteresting: word
        val re3 = ".*?"    // Non-greedy match on filler
        val re4 = "(?:[a-z][a-z]+)"    // Uninteresting: word
        val re5 = ".*?"    // Non-greedy match on filler
        val re6 = "((?:[a-z][a-z0-9_]+))"    // Word 1
        val re7 = ".+?"    // Non-greedy match on filler
        val re8 = "(.+)"    // Integer Number 1
        val p = Pattern.compile("$re1$re2$re3$re4$re5$re6$re7$re8", Pattern.CASE_INSENSITIVE or Pattern.DOTALL)
        return p.matcher(soft)
    }

    /**
     * Method to create a Matcher for finding if an url is a github one or git kernel one
     * @param url: url to check
     *
     * @return Matcher
     */
    private fun urlMatch(url: String): Matcher {
        val p = Pattern.compile(Constants.SOFTWARE_GIT, Pattern.CASE_INSENSITIVE or Pattern.DOTALL)
        return p.matcher(url)
    }

}