include $(TOPDIR)/rules.mk

PKG_NAME:=xdp-srv6-reverser
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0+
PKG_LICENSE_FILES:=

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/xdp-srv6-reverser
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libubox +libbpf +libnl-tiny
  TITLE:=XDP SRv6 Reverser
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include \
	-I$(STAGING_DIR)/usr/include/libnl-tiny

ifeq ($(CONFIG_BIG_ENDIAN),y)
export BPF_TARGET=bpfeb
else
export BPF_TARGET=bpfel
endif

define Package/xdp-srv6-reverser/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xdp-srv6-reverser $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/xdp/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/srv6_reverser_kern.o $(1)/usr/xdp/srv6_reverser_kern.o
endef

$(eval $(call BuildPackage,xdp-srv6-reverser))
