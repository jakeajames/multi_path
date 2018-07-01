include $(THEOS)/makefiles/common.mk

ARCHS = arm64

TOOL_NAME = jailbreakd
jailbreakd_FILES = $(wildcard *.m) $(wildcard *.c)
CFLAGS += -Wno-everything
jailbreakd_PRIVATE_FRAMEWORKS = IOKit AppSupport
include $(THEOS_MAKE_PATH)/tool.mk
