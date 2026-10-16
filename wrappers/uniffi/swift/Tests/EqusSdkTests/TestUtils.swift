import Foundation
import Testing

func compareJsonValues(actual: String, expected: String) {
    let actual = try! JSONSerialization.jsonObject(with: actual.data(using: .utf8)!) as! Dictionary<String, Any>
    let expected = try! JSONSerialization.jsonObject(with: expected.data(using: .utf8)!) as! Dictionary<String, Any>

    #expect(NSDictionary(dictionary: actual).isEqual(NSDictionary(dictionary: expected)))
}