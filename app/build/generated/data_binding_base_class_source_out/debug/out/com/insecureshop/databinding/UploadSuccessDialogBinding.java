// Generated by data binding compiler. Do not edit!
package com.insecureshop.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.insecureshop.R;
import java.lang.Deprecated;
import java.lang.Object;

public abstract class UploadSuccessDialogBinding extends ViewDataBinding {
  @NonNull
  public final AppCompatButton btnOk;

  @NonNull
  public final AppCompatTextView tvMessage;

  @NonNull
  public final AppCompatTextView tvSuccess;

  protected UploadSuccessDialogBinding(Object _bindingComponent, View _root, int _localFieldCount,
      AppCompatButton btnOk, AppCompatTextView tvMessage, AppCompatTextView tvSuccess) {
    super(_bindingComponent, _root, _localFieldCount);
    this.btnOk = btnOk;
    this.tvMessage = tvMessage;
    this.tvSuccess = tvSuccess;
  }

  @NonNull
  public static UploadSuccessDialogBinding inflate(@NonNull LayoutInflater inflater,
      @Nullable ViewGroup root, boolean attachToRoot) {
    return inflate(inflater, root, attachToRoot, DataBindingUtil.getDefaultComponent());
  }

  /**
   * This method receives DataBindingComponent instance as type Object instead of
   * type DataBindingComponent to avoid causing too many compilation errors if
   * compilation fails for another reason.
   * https://issuetracker.google.com/issues/116541301
   * @Deprecated Use DataBindingUtil.inflate(inflater, R.layout.upload_success_dialog, root, attachToRoot, component)
   */
  @NonNull
  @Deprecated
  public static UploadSuccessDialogBinding inflate(@NonNull LayoutInflater inflater,
      @Nullable ViewGroup root, boolean attachToRoot, @Nullable Object component) {
    return ViewDataBinding.<UploadSuccessDialogBinding>inflateInternal(inflater, R.layout.upload_success_dialog, root, attachToRoot, component);
  }

  @NonNull
  public static UploadSuccessDialogBinding inflate(@NonNull LayoutInflater inflater) {
    return inflate(inflater, DataBindingUtil.getDefaultComponent());
  }

  /**
   * This method receives DataBindingComponent instance as type Object instead of
   * type DataBindingComponent to avoid causing too many compilation errors if
   * compilation fails for another reason.
   * https://issuetracker.google.com/issues/116541301
   * @Deprecated Use DataBindingUtil.inflate(inflater, R.layout.upload_success_dialog, null, false, component)
   */
  @NonNull
  @Deprecated
  public static UploadSuccessDialogBinding inflate(@NonNull LayoutInflater inflater,
      @Nullable Object component) {
    return ViewDataBinding.<UploadSuccessDialogBinding>inflateInternal(inflater, R.layout.upload_success_dialog, null, false, component);
  }

  public static UploadSuccessDialogBinding bind(@NonNull View view) {
    return bind(view, DataBindingUtil.getDefaultComponent());
  }

  /**
   * This method receives DataBindingComponent instance as type Object instead of
   * type DataBindingComponent to avoid causing too many compilation errors if
   * compilation fails for another reason.
   * https://issuetracker.google.com/issues/116541301
   * @Deprecated Use DataBindingUtil.bind(view, component)
   */
  @Deprecated
  public static UploadSuccessDialogBinding bind(@NonNull View view, @Nullable Object component) {
    return (UploadSuccessDialogBinding)bind(component, view, R.layout.upload_success_dialog);
  }
}