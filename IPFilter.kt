package ipFilter

import kotlin.math.pow

const val OCTET_SIZE = 256.0
const val NUM_OF_OCTETS = 4

class IPFilter(suspiciousIPList: Array<String>) {
    private var suspiciousIPsAsLongs: HashSet<Long> = HashSet()

    init {
        for (IP in suspiciousIPList) {
            suspiciousIPsAsLongs.add(ipToLong(IP))
        }
    }

    private fun ipToLong(ipAddress: String): Long {
        val ipAddressInArray = convertIpAddressToArray(ipAddress)
        return convertIpToLong(ipAddressInArray)
    }

    private fun convertIpToLong(ipAddressInArray: List<String>): Long {
        var ipAsLong: Long = 0
        for (i in ipAddressInArray.indices) {
            val exponent = (NUM_OF_OCTETS - 1 - i).toDouble()
            val octetAsInt = ipAddressInArray[i].toInt()
            ipAsLong += (octetAsInt * OCTET_SIZE.pow(exponent)).toLong()
        }
        return ipAsLong
    }

    private fun convertIpAddressToArray(ipAddress: String): List<String> {
        val ipAddressWithoutPrefix = removePrefixFromIpAddress(ipAddress)
        return splitIpAddressIntoArray(ipAddressWithoutPrefix, ipAddress)
    }

    private fun splitIpAddressIntoArray(ipAddressWithoutPrefix: String, ipAddress: String): List<String> {
        val ipAddressWithoutPrefixInArray = ipAddressWithoutPrefix.split(".")
        if (ipAddressWithoutPrefixInArray.size != 4)
            throw Exception("IP \"$ipAddress\" is not divided into four parts.")
        return ipAddressWithoutPrefixInArray
    }

    private fun removePrefixFromIpAddress(ipAddress: String): String {
        val ipAddressInArray = ipAddress.split("/")
        if (ipAddressInArray.size != 2)
            throw Exception("Wrong amount of slashes in the IP address given: \"$ipAddress\". Usage: <ip_address>/CIDR_prefix")
        return ipAddressInArray[0]
    }


    fun isAllowed(inquiredIP: String): Boolean {
        val inquiredIPAsLong = ipToLong(inquiredIP)
        return !suspiciousIPsAsLongs.contains(inquiredIPAsLong)
    }
}

