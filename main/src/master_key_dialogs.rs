//! 主密钥「修改」与「重置」弹窗
//!
//! 与 `home_tab/encryption.rs` 里的首次设置 / 解锁弹窗分开：那两个场景只需要
//! 一个输入框，而修改需要「旧密钥 + 新密钥 + 确认新密钥」，重置则需要强提示
//! 与确认词，混在一个弹窗里会让每个场景都背上无关输入框。

use gpui::prelude::FluentBuilder as _;
use gpui::{App, AppContext, ParentElement, Styled, Window, div, px};
use gpui_component::input::{Input, InputState};
use gpui_component::switch::Switch;
use gpui_component::{ActiveTheme as _, WindowExt as _, h_flex, v_flex};
use rust_i18n::t;

use crate::master_key_flow::{self, RESET_CONFIRM_WORD, ResetScope};

/// 主密钥弹窗成功后的回调（用于让调用方刷新界面状态）
pub type MasterKeyDialogCallback = Box<dyn Fn(&mut App) + 'static>;

/// 用 `Rc<RefCell<..>>` 包一层：`open_dialog` 的 build 闭包与 `Dialog::on_ok`
/// 都要求 `Fn`，不能把捕获的回调值移出来。`Rc` 让每个闭包各自持有一份引用，
/// `RefCell` 让回调能取出后置空——它本就该只触发一次。
fn shared_callback(
    callback: Option<MasterKeyDialogCallback>,
) -> std::rc::Rc<std::cell::RefCell<Option<MasterKeyDialogCallback>>> {
    std::rc::Rc::new(std::cell::RefCell::new(callback))
}

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
    let on_success = shared_callback(on_success);
    // 云端重加密的结果提示要在异步任务结束后才弹，这里先把"怎么弹"封好
    let window_handle = window.window_handle();
    let notifier: Option<master_key_flow::CloudReencryptNotifier> =
        Some(Box::new(move |cx: &mut App, message: String| {
            let _ = cx.update_window(window_handle, |_, window, cx| {
                window.push_notification(message, cx);
            });
        }));
    let notifier = std::rc::Rc::new(std::cell::RefCell::new(notifier));

    let old_for_ok = old_input.clone();
    let new_for_ok = new_input.clone();
    let confirm_for_ok = confirm_input.clone();
    let error_for_ok = error_message.clone();
    let old_for_render = old_input.clone();
    let new_for_render = new_input.clone();
    let confirm_for_render = confirm_input.clone();
    let error_for_render = error_message.clone();

    window.open_dialog(cx, move |dialog, _window, cx| {
        let on_success = on_success.clone();
        let notifier = notifier.clone();
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

                match master_key_flow::apply_change_master_key(
                    &old_key,
                    &new_key,
                    notifier.borrow_mut().take(),
                    cx,
                ) {
                    Ok(outcome) => {
                        tracing::info!(
                            "主密钥修改完成：连接 {}，钥匙串 {}，团队密钥缓存 {}，版本 {}，云端重加密已启动 {}",
                            outcome.connections,
                            outcome.credentials,
                            outcome.team_key_caches,
                            outcome.key_version,
                            outcome.cloud_reencrypt_started
                        );
                        // 本地结果始终用同一条文案；需要等云端重写时再补一句进度说明，
                        // 云端重写最终的成功 / 失败由异步任务结束后单独提示一次。
                        let mut message = t!(
                            "Encryption.change_master_key_success",
                            connections = outcome.connections,
                            credentials = outcome.credentials,
                            team_keys = outcome.team_key_caches,
                            version = outcome.key_version
                        )
                        .to_string();
                        if outcome.cloud_reencrypt_started {
                            message.push('\n');
                            message.push_str(&t!("Encryption.cloud_reencrypt_in_progress"));
                        }
                        window.push_notification(message, cx);
                        if let Some(callback) = on_success.borrow_mut().take() {
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

    let confirm_input = cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(t!("Encryption.reset_master_key_confirm_placeholder"))
            .masked(false)
    });
    let error_message = cx.new(|_| Option::<String>::None);
    let on_success = shared_callback(on_success);

    let confirm_for_ok = confirm_input.clone();
    let error_for_ok = error_message.clone();
    let confirm_for_render = confirm_input.clone();
    let error_for_render = error_message.clone();

    window.open_dialog(cx, move |dialog, _window, cx| {
        let on_success = on_success.clone();
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

                // 勾选项是弹窗里现场改的，执行前重新读一次全局范围
                let scope = master_key_flow::reset_scope(cx);
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
                        if let Some(callback) = on_success.borrow_mut().take() {
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
                    .child(reset_scope_row(
                        "reset-scope-team-data",
                        t!("Encryption.reset_scope_team_data").to_string(),
                        t!("Encryption.reset_scope_team_data_desc").to_string(),
                        scope.team_data,
                        cx,
                        |scope, checked| scope.team_data = checked,
                    ))
                    .child(reset_scope_row(
                        "reset-scope-query-history",
                        t!("Encryption.reset_scope_query_history").to_string(),
                        t!("Encryption.reset_scope_query_history_desc").to_string(),
                        scope.query_history,
                        cx,
                        |scope, checked| scope.query_history = checked,
                    ))
                    .child(reset_scope_row(
                        "reset-scope-command-history",
                        t!("Encryption.reset_scope_command_history").to_string(),
                        t!("Encryption.reset_scope_command_history_desc").to_string(),
                        scope.command_history,
                        cx,
                        |scope, checked| scope.command_history = checked,
                    ))
                    .child(reset_scope_row(
                        "reset-scope-notes",
                        t!("Encryption.reset_scope_notes").to_string(),
                        t!("Encryption.reset_scope_notes_desc").to_string(),
                        scope.notes,
                        cx,
                        |scope, checked| scope.notes = checked,
                    ))
                    .child(reset_scope_row(
                        "reset-scope-cloud-sync",
                        t!("Encryption.reset_scope_cloud_sync").to_string(),
                        t!("Encryption.reset_scope_cloud_sync_desc").to_string(),
                        scope.cloud_sync,
                        cx,
                        |scope, checked| scope.cloud_sync = checked,
                    ))
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

/// 重置范围的一行：开关打开 = 删除该项。
///
/// 开关自带内部状态，点击后自己重绘，所以这里不需要 `window.refresh()`。
fn reset_scope_row(
    id: &'static str,
    title: String,
    description: String,
    checked: bool,
    cx: &App,
    apply: fn(&mut ResetScope, bool),
) -> gpui::Div {
    h_flex()
        .justify_between()
        .items_start()
        .gap_3()
        .py_1()
        .child(
            v_flex()
                .gap_1()
                .flex_1()
                .child(div().text_sm().child(title))
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(description),
                ),
        )
        .child(Switch::new(id).checked(checked).on_click(
            move |value, _window, cx| {
                let mut scope = master_key_flow::reset_scope(cx);
                apply(&mut scope, *value);
                master_key_flow::set_reset_scope(scope, cx);
            },
        ))
}
