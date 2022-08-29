package rule

//go:generate go run ../../hack/parse_tcp_params.go

var tcpOptPrefix = "tcpopt:"

var validTCPOpts = map[string]bool{
	(tcpOptPrefix + "0"):   true, // End of Option List
	(tcpOptPrefix + "1"):   true, // No-Operation
	(tcpOptPrefix + "2"):   true, // Maximum Segment Size
	(tcpOptPrefix + "3"):   true, // Window Scale
	(tcpOptPrefix + "4"):   true, // SACK Permitted
	(tcpOptPrefix + "5"):   true, // SACK
	(tcpOptPrefix + "6"):   true, // Echo (obsoleted by option 8)
	(tcpOptPrefix + "7"):   true, // Echo Reply (obsoleted by option 8)
	(tcpOptPrefix + "8"):   true, // Timestamps
	(tcpOptPrefix + "9"):   true, // Partial Order Connection Permitted (obsolete)
	(tcpOptPrefix + "10"):  true, // Partial Order Service Profile (obsolete)
	(tcpOptPrefix + "11"):  true, // CC (obsolete)
	(tcpOptPrefix + "12"):  true, // CC.NEW (obsolete)
	(tcpOptPrefix + "13"):  true, // CC.ECHO (obsolete)
	(tcpOptPrefix + "14"):  true, // TCP Alternate Checksum Request (obsolete)
	(tcpOptPrefix + "15"):  true, // TCP Alternate Checksum Data (obsolete)
	(tcpOptPrefix + "16"):  true, // Skeeter
	(tcpOptPrefix + "17"):  true, // Bubba
	(tcpOptPrefix + "18"):  true, // Trailer Checksum Option
	(tcpOptPrefix + "19"):  true, // MD5 Signature Option (obsoleted by option 29)
	(tcpOptPrefix + "20"):  true, // SCPS Capabilities
	(tcpOptPrefix + "21"):  true, // Selective Negative Acknowledgements
	(tcpOptPrefix + "22"):  true, // Record Boundaries
	(tcpOptPrefix + "23"):  true, // Corruption experienced
	(tcpOptPrefix + "24"):  true, // SNAP
	(tcpOptPrefix + "25"):  true, // Unassigned (released 2000-12-18)
	(tcpOptPrefix + "26"):  true, // TCP Compression Filter
	(tcpOptPrefix + "27"):  true, // Quick-Start Response
	(tcpOptPrefix + "28"):  true, // User Timeout Option (also, other known unauthorized use) [***][1]
	(tcpOptPrefix + "29"):  true, // TCP Authentication Option (TCP-AO)
	(tcpOptPrefix + "30"):  true, // Multipath TCP (MPTCP)
	(tcpOptPrefix + "31"):  true, // Reserved (known unauthorized use without proper IANA assignment) [**]
	(tcpOptPrefix + "32"):  true, // Reserved (known unauthorized use without proper IANA assignment) [**]
	(tcpOptPrefix + "33"):  true, // Reserved (known unauthorized use without proper IANA assignment) [**]
	(tcpOptPrefix + "34"):  true, // TCP Fast Open Cookie
	(tcpOptPrefix + "35"):  true, // Reserved
	(tcpOptPrefix + "36"):  true, // Reserved
	(tcpOptPrefix + "37"):  true, // Reserved
	(tcpOptPrefix + "38"):  true, // Reserved
	(tcpOptPrefix + "39"):  true, // Reserved
	(tcpOptPrefix + "40"):  true, // Reserved
	(tcpOptPrefix + "41"):  true, // Reserved
	(tcpOptPrefix + "42"):  true, // Reserved
	(tcpOptPrefix + "43"):  true, // Reserved
	(tcpOptPrefix + "44"):  true, // Reserved
	(tcpOptPrefix + "45"):  true, // Reserved
	(tcpOptPrefix + "46"):  true, // Reserved
	(tcpOptPrefix + "47"):  true, // Reserved
	(tcpOptPrefix + "48"):  true, // Reserved
	(tcpOptPrefix + "49"):  true, // Reserved
	(tcpOptPrefix + "50"):  true, // Reserved
	(tcpOptPrefix + "51"):  true, // Reserved
	(tcpOptPrefix + "52"):  true, // Reserved
	(tcpOptPrefix + "53"):  true, // Reserved
	(tcpOptPrefix + "54"):  true, // Reserved
	(tcpOptPrefix + "55"):  true, // Reserved
	(tcpOptPrefix + "56"):  true, // Reserved
	(tcpOptPrefix + "57"):  true, // Reserved
	(tcpOptPrefix + "58"):  true, // Reserved
	(tcpOptPrefix + "59"):  true, // Reserved
	(tcpOptPrefix + "60"):  true, // Reserved
	(tcpOptPrefix + "61"):  true, // Reserved
	(tcpOptPrefix + "62"):  true, // Reserved
	(tcpOptPrefix + "63"):  true, // Reserved
	(tcpOptPrefix + "64"):  true, // Reserved
	(tcpOptPrefix + "65"):  true, // Reserved
	(tcpOptPrefix + "66"):  true, // Reserved
	(tcpOptPrefix + "67"):  true, // Reserved
	(tcpOptPrefix + "68"):  true, // Reserved
	(tcpOptPrefix + "69"):  true, // Encryption Negotiation (TCP-ENO)
	(tcpOptPrefix + "70"):  true, // Reserved (known unauthorized use without proper IANA assignment) [**]
	(tcpOptPrefix + "71"):  true, // Reserved
	(tcpOptPrefix + "72"):  true, // Reserved
	(tcpOptPrefix + "73"):  true, // Reserved
	(tcpOptPrefix + "74"):  true, // Reserved
	(tcpOptPrefix + "75"):  true, // Reserved
	(tcpOptPrefix + "76"):  true, // Reserved (known unauthorized use without proper IANA assignment) [**]
	(tcpOptPrefix + "77"):  true, // Reserved (known unauthorized use without proper IANA assignment) [**]
	(tcpOptPrefix + "78"):  true, // Reserved (known unauthorized use without proper IANA assignment) [**]
	(tcpOptPrefix + "79"):  true, // Reserved
	(tcpOptPrefix + "80"):  true, // Reserved
	(tcpOptPrefix + "81"):  true, // Reserved
	(tcpOptPrefix + "82"):  true, // Reserved
	(tcpOptPrefix + "83"):  true, // Reserved
	(tcpOptPrefix + "84"):  true, // Reserved
	(tcpOptPrefix + "85"):  true, // Reserved
	(tcpOptPrefix + "86"):  true, // Reserved
	(tcpOptPrefix + "87"):  true, // Reserved
	(tcpOptPrefix + "88"):  true, // Reserved
	(tcpOptPrefix + "89"):  true, // Reserved
	(tcpOptPrefix + "90"):  true, // Reserved
	(tcpOptPrefix + "91"):  true, // Reserved
	(tcpOptPrefix + "92"):  true, // Reserved
	(tcpOptPrefix + "93"):  true, // Reserved
	(tcpOptPrefix + "94"):  true, // Reserved
	(tcpOptPrefix + "95"):  true, // Reserved
	(tcpOptPrefix + "96"):  true, // Reserved
	(tcpOptPrefix + "97"):  true, // Reserved
	(tcpOptPrefix + "98"):  true, // Reserved
	(tcpOptPrefix + "99"):  true, // Reserved
	(tcpOptPrefix + "100"): true, // Reserved
	(tcpOptPrefix + "101"): true, // Reserved
	(tcpOptPrefix + "102"): true, // Reserved
	(tcpOptPrefix + "103"): true, // Reserved
	(tcpOptPrefix + "104"): true, // Reserved
	(tcpOptPrefix + "105"): true, // Reserved
	(tcpOptPrefix + "106"): true, // Reserved
	(tcpOptPrefix + "107"): true, // Reserved
	(tcpOptPrefix + "108"): true, // Reserved
	(tcpOptPrefix + "109"): true, // Reserved
	(tcpOptPrefix + "110"): true, // Reserved
	(tcpOptPrefix + "111"): true, // Reserved
	(tcpOptPrefix + "112"): true, // Reserved
	(tcpOptPrefix + "113"): true, // Reserved
	(tcpOptPrefix + "114"): true, // Reserved
	(tcpOptPrefix + "115"): true, // Reserved
	(tcpOptPrefix + "116"): true, // Reserved
	(tcpOptPrefix + "117"): true, // Reserved
	(tcpOptPrefix + "118"): true, // Reserved
	(tcpOptPrefix + "119"): true, // Reserved
	(tcpOptPrefix + "120"): true, // Reserved
	(tcpOptPrefix + "121"): true, // Reserved
	(tcpOptPrefix + "122"): true, // Reserved
	(tcpOptPrefix + "123"): true, // Reserved
	(tcpOptPrefix + "124"): true, // Reserved
	(tcpOptPrefix + "125"): true, // Reserved
	(tcpOptPrefix + "126"): true, // Reserved
	(tcpOptPrefix + "127"): true, // Reserved
	(tcpOptPrefix + "128"): true, // Reserved
	(tcpOptPrefix + "129"): true, // Reserved
	(tcpOptPrefix + "130"): true, // Reserved
	(tcpOptPrefix + "131"): true, // Reserved
	(tcpOptPrefix + "132"): true, // Reserved
	(tcpOptPrefix + "133"): true, // Reserved
	(tcpOptPrefix + "134"): true, // Reserved
	(tcpOptPrefix + "135"): true, // Reserved
	(tcpOptPrefix + "136"): true, // Reserved
	(tcpOptPrefix + "137"): true, // Reserved
	(tcpOptPrefix + "138"): true, // Reserved
	(tcpOptPrefix + "139"): true, // Reserved
	(tcpOptPrefix + "140"): true, // Reserved
	(tcpOptPrefix + "141"): true, // Reserved
	(tcpOptPrefix + "142"): true, // Reserved
	(tcpOptPrefix + "143"): true, // Reserved
	(tcpOptPrefix + "144"): true, // Reserved
	(tcpOptPrefix + "145"): true, // Reserved
	(tcpOptPrefix + "146"): true, // Reserved
	(tcpOptPrefix + "147"): true, // Reserved
	(tcpOptPrefix + "148"): true, // Reserved
	(tcpOptPrefix + "149"): true, // Reserved
	(tcpOptPrefix + "150"): true, // Reserved
	(tcpOptPrefix + "151"): true, // Reserved
	(tcpOptPrefix + "152"): true, // Reserved
	(tcpOptPrefix + "153"): true, // Reserved
	(tcpOptPrefix + "154"): true, // Reserved
	(tcpOptPrefix + "155"): true, // Reserved
	(tcpOptPrefix + "156"): true, // Reserved
	(tcpOptPrefix + "157"): true, // Reserved
	(tcpOptPrefix + "158"): true, // Reserved
	(tcpOptPrefix + "159"): true, // Reserved
	(tcpOptPrefix + "160"): true, // Reserved
	(tcpOptPrefix + "161"): true, // Reserved
	(tcpOptPrefix + "162"): true, // Reserved
	(tcpOptPrefix + "163"): true, // Reserved
	(tcpOptPrefix + "164"): true, // Reserved
	(tcpOptPrefix + "165"): true, // Reserved
	(tcpOptPrefix + "166"): true, // Reserved
	(tcpOptPrefix + "167"): true, // Reserved
	(tcpOptPrefix + "168"): true, // Reserved
	(tcpOptPrefix + "169"): true, // Reserved
	(tcpOptPrefix + "170"): true, // Reserved
	(tcpOptPrefix + "171"): true, // Reserved
	(tcpOptPrefix + "172"): true, // Accurate ECN Order 0 (AccECN0) (TEMPORARY - registered 2022-08-03, expires 2023-08-03)
	(tcpOptPrefix + "173"): true, // Reserved
	(tcpOptPrefix + "174"): true, // Accurate ECN Order 1 (AccECN1) (TEMPORARY - registered 2022-08-03, expires 2023-08-03)
	(tcpOptPrefix + "175"): true, // Reserved
	(tcpOptPrefix + "176"): true, // Reserved
	(tcpOptPrefix + "177"): true, // Reserved
	(tcpOptPrefix + "178"): true, // Reserved
	(tcpOptPrefix + "179"): true, // Reserved
	(tcpOptPrefix + "180"): true, // Reserved
	(tcpOptPrefix + "181"): true, // Reserved
	(tcpOptPrefix + "182"): true, // Reserved
	(tcpOptPrefix + "183"): true, // Reserved
	(tcpOptPrefix + "184"): true, // Reserved
	(tcpOptPrefix + "185"): true, // Reserved
	(tcpOptPrefix + "186"): true, // Reserved
	(tcpOptPrefix + "187"): true, // Reserved
	(tcpOptPrefix + "188"): true, // Reserved
	(tcpOptPrefix + "189"): true, // Reserved
	(tcpOptPrefix + "190"): true, // Reserved
	(tcpOptPrefix + "191"): true, // Reserved
	(tcpOptPrefix + "192"): true, // Reserved
	(tcpOptPrefix + "193"): true, // Reserved
	(tcpOptPrefix + "194"): true, // Reserved
	(tcpOptPrefix + "195"): true, // Reserved
	(tcpOptPrefix + "196"): true, // Reserved
	(tcpOptPrefix + "197"): true, // Reserved
	(tcpOptPrefix + "198"): true, // Reserved
	(tcpOptPrefix + "199"): true, // Reserved
	(tcpOptPrefix + "200"): true, // Reserved
	(tcpOptPrefix + "201"): true, // Reserved
	(tcpOptPrefix + "202"): true, // Reserved
	(tcpOptPrefix + "203"): true, // Reserved
	(tcpOptPrefix + "204"): true, // Reserved
	(tcpOptPrefix + "205"): true, // Reserved
	(tcpOptPrefix + "206"): true, // Reserved
	(tcpOptPrefix + "207"): true, // Reserved
	(tcpOptPrefix + "208"): true, // Reserved
	(tcpOptPrefix + "209"): true, // Reserved
	(tcpOptPrefix + "210"): true, // Reserved
	(tcpOptPrefix + "211"): true, // Reserved
	(tcpOptPrefix + "212"): true, // Reserved
	(tcpOptPrefix + "213"): true, // Reserved
	(tcpOptPrefix + "214"): true, // Reserved
	(tcpOptPrefix + "215"): true, // Reserved
	(tcpOptPrefix + "216"): true, // Reserved
	(tcpOptPrefix + "217"): true, // Reserved
	(tcpOptPrefix + "218"): true, // Reserved
	(tcpOptPrefix + "219"): true, // Reserved
	(tcpOptPrefix + "220"): true, // Reserved
	(tcpOptPrefix + "221"): true, // Reserved
	(tcpOptPrefix + "222"): true, // Reserved
	(tcpOptPrefix + "223"): true, // Reserved
	(tcpOptPrefix + "224"): true, // Reserved
	(tcpOptPrefix + "225"): true, // Reserved
	(tcpOptPrefix + "226"): true, // Reserved
	(tcpOptPrefix + "227"): true, // Reserved
	(tcpOptPrefix + "228"): true, // Reserved
	(tcpOptPrefix + "229"): true, // Reserved
	(tcpOptPrefix + "230"): true, // Reserved
	(tcpOptPrefix + "231"): true, // Reserved
	(tcpOptPrefix + "232"): true, // Reserved
	(tcpOptPrefix + "233"): true, // Reserved
	(tcpOptPrefix + "234"): true, // Reserved
	(tcpOptPrefix + "235"): true, // Reserved
	(tcpOptPrefix + "236"): true, // Reserved
	(tcpOptPrefix + "237"): true, // Reserved
	(tcpOptPrefix + "238"): true, // Reserved
	(tcpOptPrefix + "239"): true, // Reserved
	(tcpOptPrefix + "240"): true, // Reserved
	(tcpOptPrefix + "241"): true, // Reserved
	(tcpOptPrefix + "242"): true, // Reserved
	(tcpOptPrefix + "243"): true, // Reserved
	(tcpOptPrefix + "244"): true, // Reserved
	(tcpOptPrefix + "245"): true, // Reserved
	(tcpOptPrefix + "246"): true, // Reserved
	(tcpOptPrefix + "247"): true, // Reserved
	(tcpOptPrefix + "248"): true, // Reserved
	(tcpOptPrefix + "249"): true, // Reserved
	(tcpOptPrefix + "250"): true, // Reserved
	(tcpOptPrefix + "251"): true, // Reserved
	(tcpOptPrefix + "252"): true, // Reserved
	(tcpOptPrefix + "253"): true, // RFC3692-style Experiment 1 (also improperly used for shipping products) [*]
	(tcpOptPrefix + "254"): true, // RFC3692-style Experiment 2 (also improperly used for shipping products) [*]
}
