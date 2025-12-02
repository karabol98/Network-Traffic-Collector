from sigma_scheduler.app.sigma_field_mapper import add_field_mapping

if __name__ == "__main__":
    add_field_mapping(
        rule_index_id=1,        # βάλε το ID που πήρες από το προηγούμενο βήμα
        sigma_field="Image",    # από το YAML του rule
        index_field="process_path"  # πεδίο του index σου
    )
