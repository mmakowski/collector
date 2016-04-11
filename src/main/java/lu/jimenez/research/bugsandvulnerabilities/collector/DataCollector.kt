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
package lu.jimenez.research.bugsandvulnerabilities.collector

import lu.jimenez.research.bugsandvulnerabilities.collector.constants.Constants
import java.util.*


class DataCollector(repositoryPath: String, savingFolder: String) {



    companion object run {

        @JvmStatic
        fun main(args: Array<String>) {
            if (args.size > 0 && args.size < 3) {
                val repositoryPath = args[0]
                val savingFolder: String
                if (args.size == 2)
                    savingFolder = args[1]
                else savingFolder = this.javaClass.classLoader.getResource("").path

                loadingProperties()

                //Creation of the class
                val dataCollector = DataCollector(repositoryPath, savingFolder)

            } else {
                println("Incorrect number of Arguments! \n Should be 1 or 2 arguments")
                return
            }

        }

        fun loadingProperties() {
            val inputStream = this.javaClass.classLoader.getResourceAsStream("collector.properties")

            val properties = Properties()
            properties.load(inputStream)
            inputStream.close()
            Constants.NB_THREAD = properties.getProperty("nbThreads").toInt()
            Constants.SOFTWARE = properties.getProperty("software")
            Constants.YEAR_BEGINNING= properties.getProperty("yearBeginning").toInt()
            Constants.YEAR_END=properties.getProperty("yearEnd").toInt()
            Constants.SOFTWARE_GIT=properties.getProperty("softwareGit")
            Constants.JYTHON = properties.getProperty("jython")
            Constants.FILE_EXTENSION = properties.getProperty("extension")
            Constants.BUG_TRACKER = properties.getProperty("bugTracker")

        }
    }
}

