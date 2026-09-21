"""Guard Schema coverage and reproducibility of the public field reference."""
import json
import unittest
from src.dataasset import build_field_reference as reference


class FieldReferenceTests(unittest.TestCase):
    def setUp(self):
        self.spec = reference.load_json(reference.EVIDENCE_SPEC)
        self.matrix = reference.load_json(reference.MATRIX_PATH)
        self.schema = reference.load_json(reference.DATAASSET / "schema/data-asset.schema.json")

    def test_schema_and_minimum_fields_are_covered(self):
        """A newly added asset type must not disappear behind a stale type list."""
        _, derived = reference.build_merged_asset(self.spec, self.matrix, self.schema)
        self.assertEqual(set(derived["fields_by_asset_type"]), set(self.schema["properties"]["asset_type"]["enum"]))
        for kind, requirements in self.spec["by_asset_type"].items():
            for bucket in ("required", "strongly_recommended", "recommended"):
                self.assertTrue(set(requirements.get(bucket, [])) <= set(derived["fields_by_asset_type"][kind]), (kind, bucket))

    def test_unknown_spec_type_is_rejected(self):
        """A typo in a specification must fail rather than lose its fields silently."""
        self.spec["by_asset_type"]["unknown_test_type"] = {"required": ["unique_field"]}
        with self.assertRaisesRegex(ValueError, "unknown_test_type"):
            reference.build_merged_asset(self.spec, self.matrix, self.schema)

    def test_new_schema_type_is_included(self):
        self.schema["properties"]["asset_type"]["enum"].append("future_test_type")
        _, derived = reference.build_merged_asset(self.spec, self.matrix, self.schema)
        self.assertIn("timestamp", derived["fields_by_asset_type"]["future_test_type"])

    def test_checked_in_reference_is_current(self):
        asset, derived = reference.build_merged_asset(self.spec, self.matrix, self.schema)
        published = reference.load_json(reference.EXAMPLES / "reference-assets.json")
        self.assertEqual(asset, published["asset"])
        self.assertEqual(derived, published["_derived"])


if __name__ == "__main__":
    unittest.main()
