// Package cigates holds repo-wide invariant checks that need no language toolchain
// beyond Go itself.
//
// # WHY THE ANDROID MANIFEST GATE LIVES HERE AND NOT IN GRADLE
//
// Spec Phase 0 requires an "Android manifest lint gate" (§6.32, HR-8.5) in CI. The
// obvious home is `gradle lint`, and that is where the *rest* of Android linting belongs.
// But a gate that only runs when a full Android toolchain is present is a gate that
// silently does not run — on a fresh checkout, in a container without the SDK, or on the
// day someone bumps AGP and the build breaks for an unrelated reason.
//
// implementation-workflow.md §6 is explicit about why that matters: "a gate that is too
// slow gets disabled, and a disabled gate is worse than no gate because everyone believes
// it is running." So the security-relevant half of the manifest check is implemented here
// as a plain text/XML assertion that runs in milliseconds with no SDK, no Gradle, and no
// network. `gradle lint` still runs for everything else.
package cigates

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const manifestPath = "../../android/app/src/main/AndroidManifest.xml"

func manifest(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", manifestPath, err)
	}
	return string(b)
}

// stripComments removes XML comments so a rule "explained in a comment" is never mistaken
// for a rule applied. The .proto absence tests hit this same trap: the document
// legitimately mentions every forbidden thing while explaining why it is absent.
func stripComments(s string) string {
	return regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(s, "")
}

// HR-8.5 / §6.32. Each of these is a one-line manifest attribute whose absence is a real
// weakness, which is exactly the kind of thing that gets lost in a review and caught by a
// grep.
func TestManifestHardening(t *testing.T) {
	m := stripComments(manifest(t))

	required := []struct {
		attr string
		why  string
	}{
		{`android:allowBackup="false"`,
			"adb backup would otherwise copy app data off the device, and this app holds the pairing state"},
		{`android:usesCleartextTraffic="false"`,
			"HR-4.9 pins the control plane; cleartext would make the pin pointless"},
	}

	// GATE 3, SECOND PASS - this check was REMOVED, deliberately, because `gradle lint`
	// disagreed with it and lint was right.
	//
	// The original required `android:debuggable="false"` in the manifest. Android lint
	// flags that as HardcodedDebugMode (severity: Fatal), and the reasoning holds: AGP
	// injects the value per build type, so hardcoding it in the manifest can mask what the
	// build type actually produced. The attribute is the wrong artifact to assert against.
	//
	// HR-8.5's property - "no debuggable release builds" - is unchanged and is now checked
	// where it is actually decided, in TestReleaseBuildTypeIsNotDebuggable below. Asserting
	// the manifest attribute was checking a value that does not control the outcome.

	for _, r := range required {
		if !strings.Contains(m, r.attr) {
			t.Errorf("HR-8.5: manifest must set %s\n  why: %s", r.attr, r.why)
		}
	}
}

// HR-8.5: "no exported components, android:exported=\"false\" wherever possible".
//
// An exported component is reachable by any other app on the device. For a remote-desktop
// client that is an IPC surface into the process holding the Keystore-backed identity.
func TestNoExportedComponents(t *testing.T) {
	m := stripComments(manifest(t))

	if strings.Contains(m, `android:exported="true"`) {
		t.Errorf("HR-8.5: no component may be exported. Found android:exported=\"true\".\n" +
			"An exported component is an IPC surface any installed app can reach, into the " +
			"process that holds the Keystore-backed device identity (HR-4.4).")
	}

	// Every activity, service, receiver and provider must state `exported` explicitly.
	// The platform default changed across API levels, so silence is not safety — it is a
	// value that depends on which SDK happened to build it.
	for _, tag := range []string{"<activity", "<service", "<receiver", "<provider"} {
		for _, decl := range strings.Split(m, tag)[1:] {
			end := strings.IndexAny(decl, ">")
			if end < 0 {
				continue
			}
			if !strings.Contains(decl[:end], "android:exported") {
				t.Errorf("HR-8.5: %s... does not state android:exported explicitly.\n"+
					"  declaration: %s", tag, strings.TrimSpace(decl[:end]))
			}
		}
	}
}

// HR-8.5: "network security config pinning the control plane".
func TestNetworkSecurityConfigPresent(t *testing.T) {
	m := stripComments(manifest(t))
	if !strings.Contains(m, "android:networkSecurityConfig=") {
		t.Error("HR-8.5: manifest must reference a network security config; it is where " +
			"the control-plane pin of HR-4.9 is declared")
	}
}

// HR-14.1 and HR-10.7's never-logged list, checked at the permission level.
//
// The audit scope of HR-10.7 has "no code path" for microphone, camera, location, or
// filesystem contents. A permission is the beginning of a code path, so requesting one is
// the earliest visible sign that the never-logged list is about to be violated — and
// HR-10.8 says that moment is when this stops being a remote-access tool and becomes
// monitoring software.
func TestNoSurveillancePermissions(t *testing.T) {
	m := stripComments(manifest(t))

	forbidden := []string{
		"RECORD_AUDIO",
		"CAMERA",
		"ACCESS_FINE_LOCATION",
		"ACCESS_COARSE_LOCATION",
		"ACCESS_BACKGROUND_LOCATION",
		"READ_SMS",
		"READ_CONTACTS",
		"READ_CALL_LOG",
		"QUERY_ALL_PACKAGES", // reveals installed apps: HR-10.7 forbids "applications launched"
		"PACKAGE_USAGE_STATS",
		"BIND_ACCESSIBILITY_SERVICE", // §6.10 names this as the client-side compromise vector
	}

	for _, p := range forbidden {
		if strings.Contains(m, p) {
			t.Errorf("HR-10.7 / HR-10.8: manifest requests %s.\n"+
				"That permission has no place in a remote-access client, and HR-10.8 is "+
				"explicit: adding from the never-logged list is the moment this becomes "+
				"monitoring software.", p)
		}
	}
}

// Positive control. If the manifest ever fails to load or the comment stripper
// over-matches, every test above would pass while inspecting nothing.
func TestManifestGateCanSeeTheManifest(t *testing.T) {
	m := stripComments(manifest(t))
	for _, expected := range []string{"<manifest", "<application", "</manifest>"} {
		if !strings.Contains(m, expected) {
			t.Fatalf("the manifest gate is inspecting nothing; missing %q. "+
				"A vacuous pass here would hide every other failure in this file.", expected)
		}
	}
}

// HR-8.5: "no debuggable release builds", checked where the value is actually decided.
//
// Replaces a manifest-attribute assertion that Android lint correctly flagged as
// HardcodedDebugMode. The release build type is what determines whether the shipped APK
// is debuggable; the manifest attribute does not.
func TestReleaseBuildTypeIsNotDebuggable(t *testing.T) {
	const gradlePath = "../../android/app/build.gradle.kts"
	b, err := os.ReadFile(gradlePath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", gradlePath, err)
	}

	release := strings.SplitN(string(b), "release {", 2)
	if len(release) < 2 {
		t.Fatal("no `release {` build type found in app/build.gradle.kts")
	}
	body := release[1]
	if end := strings.Index(body, "debug {"); end > 0 {
		body = body[:end]
	}

	if !strings.Contains(body, "isDebuggable = false") {
		t.Errorf("HR-8.5: the release build type must set isDebuggable = false. Found: %s",
			strings.TrimSpace(body))
	}
	if strings.Contains(body, "isDebuggable = true") {
		t.Error("HR-8.5: the release build type sets isDebuggable = true")
	}
}

// The manifest must NOT hardcode android:debuggable, per Android lint HardcodedDebugMode.
//
// This is the inverse of what this file originally asserted. `gradle lint` disagreed with
// the first version and lint was right: AGP injects the value per build type, so a
// hardcoded manifest attribute can mask what the release build actually produced.
func TestManifestDoesNotHardcodeDebuggable(t *testing.T) {
	if strings.Contains(stripComments(manifest(t)), "android:debuggable") {
		t.Error("android:debuggable must not appear in the manifest; AGP injects it per " +
			"build type. Android lint flags this as HardcodedDebugMode (Fatal).")
	}
}
