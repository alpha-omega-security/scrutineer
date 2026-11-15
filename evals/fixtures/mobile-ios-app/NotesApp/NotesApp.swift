import SwiftUI

@main
struct NotesApp: App {
    @State private var openedNote: String?

    var body: some Scene {
        WindowGroup {
            Text(openedNote ?? "Notes")
                .onOpenURL { url in
                    guard url.scheme == "notes", url.host == "open" else { return }
                    openedNote = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                        .queryItems?.first(where: { $0.name == "id" })?.value
                }
        }
    }
}
