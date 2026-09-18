.PHONY: test tools setup-signing icon app install installer version release release-notes

VERSION := $(shell /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Config/AppInfo.plist)
MODULE_CACHE := CLANG_MODULE_CACHE_PATH="$(CURDIR)/.build/module-cache" SWIFT_MODULECACHE_PATH="$(CURDIR)/.build/module-cache"
# The last binary build-vpn-tools.sh writes: missing, or older than the script
# (a bumped engine tag), means the engines are built again.
TOOLS := Vendor/bin/arm64/openvpn

test:
	mkdir -p .build/module-cache
	$(MODULE_CACHE) swift test --disable-sandbox

tools:
	./scripts/build-vpn-tools.sh

$(TOOLS): scripts/build-vpn-tools.sh
	./scripts/build-vpn-tools.sh

# Does nothing once the certificate exists.
setup-signing:
	./scripts/setup-local-signing.sh

# Only after changing scripts/make-icon.swift: the .icns and .png are committed.
icon:
	rm -rf .build/AppIcon.iconset && mkdir -p .build/module-cache .build/AppIcon.iconset
	$(MODULE_CACHE) swift scripts/make-icon.swift .build/icon-1024.png
	for s in 16 32 128 256 512; do \
		sips -z $$s $$s .build/icon-1024.png --out .build/AppIcon.iconset/icon_$${s}x$${s}.png >/dev/null; \
		sips -z $$((s * 2)) $$((s * 2)) .build/icon-1024.png --out .build/AppIcon.iconset/icon_$${s}x$${s}@2x.png >/dev/null; \
	done
	iconutil -c icns .build/AppIcon.iconset -o Config/AppIcon.icns
	sips -z 256 256 .build/icon-1024.png --out Config/AppIcon.png >/dev/null

app: $(TOOLS)
	./scripts/build-app.sh

install: app
	./scripts/install-local.sh

installer: app
	./scripts/build-installer.sh

# make version V=1.0.7: both places the version lives, plus the build number.
version:
	@test -n "$(V)" || { echo "Укажите версию: make version V=1.0.7"; exit 1; }
	@N=$$(( $$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' Config/AppInfo.plist) + 1 )); \
	sed -i '' -e '/CFBundleShortVersionString/s|<string>[^<]*</string>|<string>$(V)</string>|' \
		-e "/CFBundleVersion</s|<string>[^<]*</string>|<string>$$N</string>|" Config/AppInfo.plist; \
	sed -i '' 's/static let current = ".*"/static let current = "$(V)"/' Sources/VPNRouterCore/Models.swift; \
	echo "Версия $(V), сборка $$N. Закоммитьте, запушьте и выполните make release NOTES=\"что нового\""

# Checked before the long build, not after it.
release-notes:
	@test -n "$$NOTES" || { echo "Нет описания релиза: make release NOTES=\"что нового\""; exit 1; }

# One command from sources to a GitHub Release. The package is built from the
# pushed commit and the tag lands on it, so what users get is what is in git.
release: release-notes setup-signing test installer
	@command -v gh >/dev/null || { echo "Нужен GitHub CLI, один раз: brew install gh && gh auth login"; exit 1; }
	@git diff --quiet HEAD || { echo "Есть незакоммиченные изменения (после сборки движков — Vendor/SHA256SUMS): закоммитьте, запушьте и повторите"; exit 1; }
	@test -n "$$(git branch -r --contains HEAD)" || { echo "Коммит ещё не на GitHub: git push и повторите"; exit 1; }
	gh release create "v$(VERSION)" Build/Commutator.pkg --target "$$(git rev-parse HEAD)" --title "Commutator $(VERSION)" --notes "$$NOTES"
