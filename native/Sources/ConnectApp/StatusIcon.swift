import AppKit

enum StatusIcon {
    // Optical simplification of the application's interlocking M/tunnel ribbons.
    // A vector template keeps edges crisp and lets NSStatusBar choose the color
    // for light/dark appearances, wallpaper contrast and menu highlighting.
    static func make() -> NSImage {
        let image = NSImage(size: NSSize(width: 24, height: 18), flipped: false) { _ in
            NSColor.black.setStroke()
            let ribbon = NSBezierPath()
            ribbon.lineWidth = 2.6
            ribbon.lineCapStyle = .round
            ribbon.lineJoinStyle = .round
            ribbon.move(to: NSPoint(x: 3, y: 4))
            ribbon.curve(to: NSPoint(x: 3, y: 12), controlPoint1: NSPoint(x: 2, y: 6), controlPoint2: NSPoint(x: 2, y: 10))
            ribbon.curve(to: NSPoint(x: 8, y: 13), controlPoint1: NSPoint(x: 3, y: 15.5), controlPoint2: NSPoint(x: 5, y: 16))
            ribbon.line(to: NSPoint(x: 17, y: 4))
            ribbon.curve(to: NSPoint(x: 21, y: 5), controlPoint1: NSPoint(x: 19, y: 2), controlPoint2: NSPoint(x: 21, y: 2))
            ribbon.line(to: NSPoint(x: 21, y: 12))
            ribbon.curve(to: NSPoint(x: 16, y: 13), controlPoint1: NSPoint(x: 21, y: 15.5), controlPoint2: NSPoint(x: 19, y: 16))
            ribbon.line(to: NSPoint(x: 7, y: 4))
            ribbon.curve(to: NSPoint(x: 3, y: 4), controlPoint1: NSPoint(x: 5, y: 2), controlPoint2: NSPoint(x: 3, y: 2))
            ribbon.close()
            ribbon.stroke()
            return true
        }
        image.isTemplate = true
        return image
    }
}
