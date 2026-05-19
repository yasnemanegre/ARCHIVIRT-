<?xml version="1.0" encoding="UTF-8"?>
<!--
  ARCHIVIRT — OVS Network XSLT Transform
  Adds <virtualport type='openvswitch'/> to libvirt network XML
  so VMs connecting to OVS bridges get proper OVS port handling.
  Applied to all OVS-backed networks in networks.tf.
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" indent="yes"/>

  <!-- Copy all nodes by default -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>

  <!-- Add virtualport after bridge element -->
  <xsl:template match="bridge">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
    <virtualport type="openvswitch"/>
  </xsl:template>

</xsl:stylesheet>
