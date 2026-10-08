//! 主密钥「修改」与「重置」弹窗
//!
//! 与 `home_tab/encryption.rs` 里的首次设置 / 解锁弹窗分开：那两个场景只需要
//! 一个输入框，而修改需要「旧密钥 + 新密钥 + 确认新密钥」，重置则需要强提示
//! 与确认词，混在一个弹窗里会让每个场景都背上无关输入框。

use gpui::{App, Window, px};
use gpui_component::input::{Input, InputState};
use gpui_component::{ActiveTheme as _, WindowExt as _, h_flex, v_flex};

use crate::master_key_flow::{self, RESET_CONFIRM_WORD, ResetScope};

/// 主密钥弹窗成功后的回调（用于让调用方刷新界面状态）
pub type MasterKeyDialogCallback = Box<dyn Fn(&mut App) + 'static>;

/// 修改主密钥弹窗：旧密钥 + 新密钥 + 确认新密钥
pub fn show_change_master_key_dialog(
    window: &mut Window,
    cx: &mut App,
    on_success: Option<MasterKeyDialogCallback>,
) {
    if !one_core::crypto::has_repo_password_set() {
        window.push_notification(
            one_core::crypto::CryptoError::NoPasswordSet.to_string(),
            cx,
        );
        return;
    }

    let old_input = cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(t!("Encryption.old_password_placeholder"))
            .masked(true)
    });
    let new_input = cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(t!("Encryption.new_password_placeholder"))
            .masked(true)
    });
    let confirm_input = cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(t!("Encryption.confirm_password_placeholder"))
            .masked(true)
    });
    let error_message = cx.new(|_| Option::<String>::None);

    let old_for_ok = old_input.clone();
    let new_for_ok = new_input.clone();
    let confirm_for_ok = confirm_input.clone();
    let error_for_ok = error_message.clone();
    let old_for_render = old_input.clone();
    let new_for_render = new_input.clone();
    let confirm_for_render = confirm_input.clone();
    let error_for_render = error_message.clone();

    window.open_dialog(cx, move |dialog, _window, cx| {
        let old_for_ok = old_for_ok.clone();
        let new_for_ok = new_for_ok.clone();
        let confirm_for_ok = confirm_for_ok.clone();
        let error_for_ok = error_for_ok.clone();

        dialog
            .title(t!("Encryption.change_repo_password").to_string())
            .width(px(560.))
            .confirm()
            .on_cancel(|_, _, _| true)
            .on_ok(move |_, window, cx: &mut App| {
                let old_key = old_for_ok.read(cx).text().to_string();
                let new_key = new_for_ok.read(cx).text().to_string();
                let confirm_key = confirm_for_ok.read(cx).text().to_string();

                if old_key.is_empty() || new_key.is_empty() {
                    error_for_ok.update(cx, |message, cx| {
                        *message = Some(t!("Encryption.key_empty").to_string());
                        cx.notify();
                    });
                    return false;
                }
                if new_key != confirm_key {
                    error_for_ok.update(cx, |message, cx| {
                        *message = Some(t!("Encryption.key_mismatch").to_string());
                        cx.notify();
                    });
                    return false;
                }

                match master_key_flow::apply_change_master_key(&old_key, &new_key, cx) {
                    Ok(outcome) => {
                        tracing::info!(
                            "主密钥修改完成：连接 {}，钥匙串 {}，团队密钥缓存 {}，版本 {}，云端重加密已启动 {}",
                            outcome.connections,
                            outcome.credentials,
                            outcome.team_key_caches,
                            outcome.key_version,
                            outcome.cloud_started
                        );
                        let message = if outcome.pending_cloud {
                            t!("Encryption.change_master_key_pending").to_string()
                        } else {
                            t!(
                                "Encryption.change_master_key_success",
                                connections = outcome.connections,
                                credentials = outcome.credentials,
                                team_keys = outcome.team_key_caches,
                                version = outcome.key_version
                            )
                            .to_string()
                        };
                        window.push_notification(message, cx);
                        // on_ok 是 Fn（可能被重复调用），只能借用回调而不能消耗它
                        if let Some(callback) = &on_success {
                            callback(cx);
                        }
                        true
                    }
                    Err(error) => {
                        error_for_ok.update(cx, |message, cx| {
                            *message = Some(error);
                            cx.notify();
                        });
                        false
                    }
                }
            })
            .child(
                v_flex()
                    .gap_4()
                    .p_4()
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().warning)
                            .child(t!("Encryption.change_master_key_notice").to_string()),
                    )
                    .child(key_field(
                        t!("Encryption.old_password_label").to_string(),
                        &old_for_render,
                    ))
                    .child(key_field(
                        t!("Encryption.new_password_label").to_string(),
                        &new_for_render,
                    ))
                    .child(key_field(
                        t!("Encryption.confirm_password_label").to_string(),
                        &confirm_for_render,
                    ))
                    .when_some(error_for_render.read(cx).clone(), |this, message| {
                        this.child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().danger)
                                .child(message),
                        )
                    }),
            )
    });

    old_input.update(cx, |input, cx| input.focus(window, cx));
}

/// 重置主密钥弹窗：强提示 + 删除清单 + 输入 RESET 二次确认
pub fn show_reset_master_key_dialog(
    window: &mut Window,
    cx: &mut App,
    on_success: Option<MasterKeyDialogCallback>,
) {
    let scope = master_key_flow::reset_scope(cx);
    let deleted_labels = deleted_labels(&scope);
    let kept_labels = kept_labels(&scope);

    let confirm_input = cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(t!("Encryption.reset_master_key_confirm_placeholder"))
            .masked(false)
    });
    let error_message = cx.new(|_| Option::<String>::None);

    let confirm_for_ok = confirm_input.clone();
    let error_for_ok = error_message.clone();
    let confirm_for_render = confirm_input.clone();
    let error_for_render = error_message.clone();

    window.open_dialog(cx, move |dialog, _window, cx| {
        let confirm_for_ok = confirm_for_ok.clone();
        let error_for_ok = error_for_ok.clone();

        dialog
            .title(t!("Encryption.reset_master_key").to_string())
            .width(px(560.))
            .confirm()
            .on_cancel(|_, _, _| true)
            .on_ok(move |_, window, cx: &mut App| {
                let word = confirm_for_ok.read(cx).text().to_string();
                if word.trim() != RESET_CONFIRM_WORD {
                    error_for_ok.update(cx, |message, cx| {
                        *message = Some(t!("Encryption.reset_master_key_invalid").to_string());
                        cx.notify();
                    });
                    return false;
                }

                match master_key_flow::reset_master_key_data(scope, cx) {
                    Ok(outcome) => {
                        tracing::info!("主密钥重置完成：已删除 {} 项", outcome.deleted.len());
                        let message = if outcome.failed.is_empty() {
                            t!("Encryption.reset_master_key_done").to_string()
                        } else {
                            t!(
                                "Encryption.reset_master_key_partial",
                                error = outcome.failed.join("; ")
                            )
                            .to_string()
                        };
                        window.push_notification(message, cx);
                        if let Some(callback) = &on_success {
                            callback(cx);
                        }
                        true
                    }
                    Err(error) => {
                        error_for_ok.update(cx, |message, cx| {
                            *message = Some(error);
                            cx.notify();
                        });
                        false
                    }
                }
            })
            .child(
                v_flex()
                    .gap_3()
                    .p_4()
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().danger)
                            .child(t!("Encryption.reset_master_key_notice").to_string()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(t!("Encryption.reset_master_key_scope").to_string()),
                    )
                    .child(v_flex().gap_1().children(deleted_labels.into_iter().map(
                        |label| {
                            div()
                                .text_sm()
                                .text_color(cx.theme().danger)
                                .child(format!("• {label}"))
                        },
                    )))
                    .when(!kept_labels.is_empty(), |this| {
                        this.child(
                            div()
                                .text_sm()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(t!("Encryption.reset_master_key_kept").to_string()),
                        )
                        .child(v_flex().gap_1().children(kept_labels.into_iter().map(
                            |label| {
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(format!("• {label}"))
                            },
                        )))
                    })
                    .child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(t!("Encryption.reset_master_key_confirm_label").to_string()),
                    )
                    .child(h_flex().gap_2().child(Input::new(&confirm_for_render).w_full()))
                    .when_some(error_for_render.read(cx).clone(), |this, message| {
                        this.child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().danger)
                                .child(message),
                        )
                    }),
            )
    });

    confirm_input.update(cx, |input, cx| input.focus(window, cx));
}

fn key_field(label: String, input: &gpui::Entity<InputState>) -> gpui::Div {
    h_flex()
        .items_center()
        .gap_3()
        .child(div().text_sm().flex_shrink_0().w(px(120.)).child(label))
        .child(Input::new(input).mask_toggle().w_full())
}

fn deleted_labels(scope: &ResetScope) -> Vec<String> {
    let mut labels = vec![
        t!("Encryption.reset_scope_required").to_string(),
        t!("Encryption.reset_scope_credentials").to_string(),
    ];
    if scope.team_data {
        labels.push(t!("Encryption.reset_scope_team_data").to_string());
    }
    if scope.query_history {
        labels.push(t!("Encryption.reset_scope_query_history").to_string());
    }
    if scope.command_history {
        labels.push(t!("Encryption.reset_scope_command_history").to_string());
    }
    if scope.notes {
        labels.push(t!("Encryption.reset_scope_notes").to_string());
    }
    if scope.cloud_sync {
        labels.push(t!("Encryption.reset_scope_cloud_sync").to_string());
    }
    labels
}

fn kept_labels(scope: &ResetScope) -> Vec<String> {
    let mut labels = Vec::new();
    if !scope.team_data {
        labels.push(t!("Encryption.reset_scope_team_data").to_string());
    }
    if !scope.query_history {
        labels.push(t!("Encryption.reset_scope_query_history").to_string());
    }
    if !scope.command_history {
        labels.push(t!("Encryption.reset_scope_command_history").to_string());
    }
    if !scope.notes {
        labels.push(t!("Encryption.reset_scope_notes").to_string());
    }
    if !scope.cloud_sync {
        labels.push(t!("Encryption.reset_scope_cloud_sync").to_string());
    }
    labels
}