APP_NAME := WeChatKeep
BUILD_DIR := .build/release
BIN := $(BUILD_DIR)/WeChatKeepGUI
APP := $(APP_NAME).app

.PHONY: all build app universal clean

all: app

build:
	swift build -c release

# 当前架构的 .app
app: build
	rm -rf "$(APP)"
	mkdir -p "$(APP)/Contents/MacOS"
	cp $(BIN) "$(APP)/Contents/MacOS/$(APP_NAME)"
	plutil -create xml1 "$(APP)/Contents/Info.plist"
	plutil -insert CFBundleName -string "$(APP_NAME)" "$(APP)/Contents/Info.plist"
	plutil -insert CFBundleIdentifier -string "io.github.wxkeep.gui" "$(APP)/Contents/Info.plist"
	plutil -insert CFBundleExecutable -string "$(APP_NAME)" "$(APP)/Contents/Info.plist"
	plutil -insert LSUIElement -bool true "$(APP)/Contents/Info.plist"
	plutil -insert LSMinimumSystemVersion -string "13.0" "$(APP)/Contents/Info.plist"
	codesign -f -s - "$(APP)"
	@echo "产物: $(PWD)/$(APP)"

# universal：需在 arm64 机上交叉跑一次 x86_64 后合并（CI macos-14+ 默认 arm64）
universal:
	swift build -c release --arch arm64 --arch x86_64
	$(MAKE) app

clean:
	rm -rf .build "$(APP)"
