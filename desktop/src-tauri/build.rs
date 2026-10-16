fn main() {
    // Every app command is listed, so each window's capability must allow
    // the commands it may call: the node window cannot reach sharing or the
    // recovery key, and the Drop window cannot reach node settings or pools.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "node_status",
            "save_settings",
            "restart_node",
            "check_for_update",
            "install_update",
            "import_pool",
            "pool_status",
            "start_pool",
            "stop_pool",
            "remove_pool",
            "review_pool_cleanup",
            "clear_pool_cleanup",
            "open_pool_client",
            "platform_info",
            "drop_status",
            "set_watch_folder",
            "open_watch_folder",
            "check_online_node",
            "set_online_node",
            "approve_device",
            "renew_approval",
            "approval_status",
            "cancel_approval",
            "open_drop_flow",
            "add_paths",
            "pick_files",
            "retry",
            "copy_back",
            "save_copy",
            "remove",
            "recovery_key_for_display",
            "save_recovery_file",
            "confirm_recovery_saved",
            "restore",
            "share_start",
            "share_again",
            "share_verify",
            "share_cancel",
            "stop_sharing",
        ]),
    ))
    .expect("failed to run tauri-build");
}
