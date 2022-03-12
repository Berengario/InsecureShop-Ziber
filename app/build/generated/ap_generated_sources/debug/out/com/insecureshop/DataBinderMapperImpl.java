package com.insecureshop;

import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.View;
import androidx.databinding.DataBinderMapper;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import com.insecureshop.databinding.ActivityImplicitIntentForNonExportedBindingImpl;
import com.insecureshop.databinding.ActivityLoginBindingImpl;
import com.insecureshop.databinding.ActivityMainBindingImpl;
import com.insecureshop.databinding.ActivityPrivateBindingImpl;
import com.insecureshop.databinding.ActivityWebviewBindingImpl;
import com.insecureshop.databinding.AppLoadingDialogBindingImpl;
import com.insecureshop.databinding.BaseMainBindingImpl;
import com.insecureshop.databinding.CartItemBindingImpl;
import com.insecureshop.databinding.FragmentHomeBindingImpl;
import com.insecureshop.databinding.ProductItemBindingImpl;
import com.insecureshop.databinding.ToolbarBindingImpl;
import com.insecureshop.databinding.UploadSuccessDialogBindingImpl;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.lang.Object;
import java.lang.Override;
import java.lang.RuntimeException;
import java.lang.String;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class DataBinderMapperImpl extends DataBinderMapper {
  private static final int LAYOUT_ACTIVITYIMPLICITINTENTFORNONEXPORTED = 1;

  private static final int LAYOUT_ACTIVITYLOGIN = 2;

  private static final int LAYOUT_ACTIVITYMAIN = 3;

  private static final int LAYOUT_ACTIVITYPRIVATE = 4;

  private static final int LAYOUT_ACTIVITYWEBVIEW = 5;

  private static final int LAYOUT_APPLOADINGDIALOG = 6;

  private static final int LAYOUT_BASEMAIN = 7;

  private static final int LAYOUT_CARTITEM = 8;

  private static final int LAYOUT_FRAGMENTHOME = 9;

  private static final int LAYOUT_PRODUCTITEM = 10;

  private static final int LAYOUT_TOOLBAR = 11;

  private static final int LAYOUT_UPLOADSUCCESSDIALOG = 12;

  private static final SparseIntArray INTERNAL_LAYOUT_ID_LOOKUP = new SparseIntArray(12);

  static {
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.activity_implicit_intent_for_non_exported, LAYOUT_ACTIVITYIMPLICITINTENTFORNONEXPORTED);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.activity_login, LAYOUT_ACTIVITYLOGIN);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.activity_main, LAYOUT_ACTIVITYMAIN);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.activity_private, LAYOUT_ACTIVITYPRIVATE);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.activity_webview, LAYOUT_ACTIVITYWEBVIEW);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.app_loading_dialog, LAYOUT_APPLOADINGDIALOG);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.base_main, LAYOUT_BASEMAIN);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.cart_item, LAYOUT_CARTITEM);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.fragment_home, LAYOUT_FRAGMENTHOME);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.product_item, LAYOUT_PRODUCTITEM);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.toolbar, LAYOUT_TOOLBAR);
    INTERNAL_LAYOUT_ID_LOOKUP.put(com.insecureshop.R.layout.upload_success_dialog, LAYOUT_UPLOADSUCCESSDIALOG);
  }

  @Override
  public ViewDataBinding getDataBinder(DataBindingComponent component, View view, int layoutId) {
    int localizedLayoutId = INTERNAL_LAYOUT_ID_LOOKUP.get(layoutId);
    if(localizedLayoutId > 0) {
      final Object tag = view.getTag();
      if(tag == null) {
        throw new RuntimeException("view must have a tag");
      }
      switch(localizedLayoutId) {
        case  LAYOUT_ACTIVITYIMPLICITINTENTFORNONEXPORTED: {
          if ("layout/activity_implicit_intent_for_non_exported_0".equals(tag)) {
            return new ActivityImplicitIntentForNonExportedBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for activity_implicit_intent_for_non_exported is invalid. Received: " + tag);
        }
        case  LAYOUT_ACTIVITYLOGIN: {
          if ("layout/activity_login_0".equals(tag)) {
            return new ActivityLoginBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for activity_login is invalid. Received: " + tag);
        }
        case  LAYOUT_ACTIVITYMAIN: {
          if ("layout/activity_main_0".equals(tag)) {
            return new ActivityMainBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for activity_main is invalid. Received: " + tag);
        }
        case  LAYOUT_ACTIVITYPRIVATE: {
          if ("layout/activity_private_0".equals(tag)) {
            return new ActivityPrivateBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for activity_private is invalid. Received: " + tag);
        }
        case  LAYOUT_ACTIVITYWEBVIEW: {
          if ("layout/activity_webview_0".equals(tag)) {
            return new ActivityWebviewBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for activity_webview is invalid. Received: " + tag);
        }
        case  LAYOUT_APPLOADINGDIALOG: {
          if ("layout/app_loading_dialog_0".equals(tag)) {
            return new AppLoadingDialogBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for app_loading_dialog is invalid. Received: " + tag);
        }
        case  LAYOUT_BASEMAIN: {
          if ("layout/base_main_0".equals(tag)) {
            return new BaseMainBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for base_main is invalid. Received: " + tag);
        }
        case  LAYOUT_CARTITEM: {
          if ("layout/cart_item_0".equals(tag)) {
            return new CartItemBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for cart_item is invalid. Received: " + tag);
        }
        case  LAYOUT_FRAGMENTHOME: {
          if ("layout/fragment_home_0".equals(tag)) {
            return new FragmentHomeBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for fragment_home is invalid. Received: " + tag);
        }
        case  LAYOUT_PRODUCTITEM: {
          if ("layout/product_item_0".equals(tag)) {
            return new ProductItemBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for product_item is invalid. Received: " + tag);
        }
        case  LAYOUT_TOOLBAR: {
          if ("layout/toolbar_0".equals(tag)) {
            return new ToolbarBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for toolbar is invalid. Received: " + tag);
        }
        case  LAYOUT_UPLOADSUCCESSDIALOG: {
          if ("layout/upload_success_dialog_0".equals(tag)) {
            return new UploadSuccessDialogBindingImpl(component, view);
          }
          throw new IllegalArgumentException("The tag for upload_success_dialog is invalid. Received: " + tag);
        }
      }
    }
    return null;
  }

  @Override
  public ViewDataBinding getDataBinder(DataBindingComponent component, View[] views, int layoutId) {
    if(views == null || views.length == 0) {
      return null;
    }
    int localizedLayoutId = INTERNAL_LAYOUT_ID_LOOKUP.get(layoutId);
    if(localizedLayoutId > 0) {
      final Object tag = views[0].getTag();
      if(tag == null) {
        throw new RuntimeException("view must have a tag");
      }
      switch(localizedLayoutId) {
      }
    }
    return null;
  }

  @Override
  public int getLayoutId(String tag) {
    if (tag == null) {
      return 0;
    }
    Integer tmpVal = InnerLayoutIdLookup.sKeys.get(tag);
    return tmpVal == null ? 0 : tmpVal;
  }

  @Override
  public String convertBrIdToString(int localId) {
    String tmpVal = InnerBrLookup.sKeys.get(localId);
    return tmpVal;
  }

  @Override
  public List<DataBinderMapper> collectDependencies() {
    ArrayList<DataBinderMapper> result = new ArrayList<DataBinderMapper>(1);
    result.add(new androidx.databinding.library.baseAdapters.DataBinderMapperImpl());
    return result;
  }

  private static class InnerBrLookup {
    static final SparseArray<String> sKeys = new SparseArray<String>(1);

    static {
      sKeys.put(0, "_all");
    }
  }

  private static class InnerLayoutIdLookup {
    static final HashMap<String, Integer> sKeys = new HashMap<String, Integer>(12);

    static {
      sKeys.put("layout/activity_implicit_intent_for_non_exported_0", com.insecureshop.R.layout.activity_implicit_intent_for_non_exported);
      sKeys.put("layout/activity_login_0", com.insecureshop.R.layout.activity_login);
      sKeys.put("layout/activity_main_0", com.insecureshop.R.layout.activity_main);
      sKeys.put("layout/activity_private_0", com.insecureshop.R.layout.activity_private);
      sKeys.put("layout/activity_webview_0", com.insecureshop.R.layout.activity_webview);
      sKeys.put("layout/app_loading_dialog_0", com.insecureshop.R.layout.app_loading_dialog);
      sKeys.put("layout/base_main_0", com.insecureshop.R.layout.base_main);
      sKeys.put("layout/cart_item_0", com.insecureshop.R.layout.cart_item);
      sKeys.put("layout/fragment_home_0", com.insecureshop.R.layout.fragment_home);
      sKeys.put("layout/product_item_0", com.insecureshop.R.layout.product_item);
      sKeys.put("layout/toolbar_0", com.insecureshop.R.layout.toolbar);
      sKeys.put("layout/upload_success_dialog_0", com.insecureshop.R.layout.upload_success_dialog);
    }
  }
}
