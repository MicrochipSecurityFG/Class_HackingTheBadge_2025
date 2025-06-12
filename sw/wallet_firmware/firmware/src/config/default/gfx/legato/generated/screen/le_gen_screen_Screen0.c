#include "gfx/legato/generated/screen/le_gen_screen_Screen0.h"

// screen member widget declarations
static leWidget* root0;

leWidget* Screen0_PanelWidget_0;
leImageWidget* Screen0_ImageWidget_0;
leLabelWidget* Screen0_MenuItem_0;
leLabelWidget* Screen0_MenuItem_1;
leLabelWidget* Screen0_MenuItem_2;
leRadioButtonWidget* Screen0_RadioButtonWidget_0;


static leBool initialized = LE_FALSE;
static leBool showing = LE_FALSE;

leResult screenInit_Screen0(void)
{
    if(initialized == LE_TRUE)
        return LE_FAILURE;

    initialized = LE_TRUE;

    return LE_SUCCESS;
}

leResult screenShow_Screen0(void)
{
    if(showing == LE_TRUE)
        return LE_FAILURE;

    // layer 0
    root0 = leWidget_New();
    root0->fn->setSize(root0, LE_DEFAULT_SCREEN_WIDTH, LE_DEFAULT_SCREEN_HEIGHT);
    root0->fn->setBackgroundType(root0, LE_WIDGET_BACKGROUND_NONE);
    root0->fn->setMargins(root0, 0, 0, 0, 0);
    root0->flags |= LE_WIDGET_IGNOREEVENTS;
    root0->flags |= LE_WIDGET_IGNOREPICK;

    Screen0_PanelWidget_0 = leWidget_New();
    Screen0_PanelWidget_0->fn->setPosition(Screen0_PanelWidget_0, 0, 0);
    Screen0_PanelWidget_0->fn->setSize(Screen0_PanelWidget_0, 160, 80);
    root0->fn->addChild(root0, (leWidget*)Screen0_PanelWidget_0);

    Screen0_ImageWidget_0 = leImageWidget_New();
    Screen0_ImageWidget_0->fn->setPosition(Screen0_ImageWidget_0, 22, 0);
    Screen0_ImageWidget_0->fn->setSize(Screen0_ImageWidget_0, 120, 28);
    Screen0_ImageWidget_0->fn->setBorderType(Screen0_ImageWidget_0, LE_WIDGET_BORDER_NONE);
    Screen0_ImageWidget_0->fn->setImage(Screen0_ImageWidget_0, (leImage*)&mchpLogo_small);
    root0->fn->addChild(root0, (leWidget*)Screen0_ImageWidget_0);

    Screen0_MenuItem_0 = leLabelWidget_New();
    Screen0_MenuItem_0->fn->setPosition(Screen0_MenuItem_0, 12, 30);
    Screen0_MenuItem_0->fn->setSize(Screen0_MenuItem_0, 148, 16);
    Screen0_MenuItem_0->fn->setBackgroundType(Screen0_MenuItem_0, LE_WIDGET_BACKGROUND_NONE);
    root0->fn->addChild(root0, (leWidget*)Screen0_MenuItem_0);

    Screen0_MenuItem_1 = leLabelWidget_New();
    Screen0_MenuItem_1->fn->setPosition(Screen0_MenuItem_1, 12, 46);
    Screen0_MenuItem_1->fn->setSize(Screen0_MenuItem_1, 148, 16);
    Screen0_MenuItem_1->fn->setBackgroundType(Screen0_MenuItem_1, LE_WIDGET_BACKGROUND_NONE);
    root0->fn->addChild(root0, (leWidget*)Screen0_MenuItem_1);

    Screen0_MenuItem_2 = leLabelWidget_New();
    Screen0_MenuItem_2->fn->setPosition(Screen0_MenuItem_2, 12, 62);
    Screen0_MenuItem_2->fn->setSize(Screen0_MenuItem_2, 148, 16);
    Screen0_MenuItem_2->fn->setBackgroundType(Screen0_MenuItem_2, LE_WIDGET_BACKGROUND_NONE);
    root0->fn->addChild(root0, (leWidget*)Screen0_MenuItem_2);

    Screen0_RadioButtonWidget_0 = leRadioButtonWidget_New();
    Screen0_RadioButtonWidget_0->fn->setPosition(Screen0_RadioButtonWidget_0, 0, 30);
    Screen0_RadioButtonWidget_0->fn->setSize(Screen0_RadioButtonWidget_0, 14, 14);
    Screen0_RadioButtonWidget_0->fn->setHAlignment(Screen0_RadioButtonWidget_0, LE_HALIGN_CENTER);
    root0->fn->addChild(root0, (leWidget*)Screen0_RadioButtonWidget_0);

    leAddRootWidget(root0, 0);
    leSetLayerColorMode(0, LE_COLOR_MODE_RGB_565);

    Screen0_OnShow(); // raise event

    showing = LE_TRUE;

    return LE_SUCCESS;
}

void screenUpdate_Screen0(void)
{
    root0->fn->setSize(root0, root0->rect.width, root0->rect.height);

    Screen0_OnUpdate(); // raise event
}

void screenHide_Screen0(void)
{
    Screen0_OnHide(); // raise event


    leRemoveRootWidget(root0, 0);
    leWidget_Delete(root0);
    root0 = NULL;

    Screen0_PanelWidget_0 = NULL;
    Screen0_ImageWidget_0 = NULL;
    Screen0_MenuItem_0 = NULL;
    Screen0_MenuItem_1 = NULL;
    Screen0_MenuItem_2 = NULL;
    Screen0_RadioButtonWidget_0 = NULL;


    showing = LE_FALSE;
}

void screenDestroy_Screen0(void)
{
    if(initialized == LE_FALSE)
        return;

    initialized = LE_FALSE;
}

leWidget* screenGetRoot_Screen0(uint32_t lyrIdx)
{
    if(lyrIdx >= LE_LAYER_COUNT)
        return NULL;

    switch(lyrIdx)
    {
        case 0:
        {
            return root0;
        }
        default:
        {
            return NULL;
        }
    }
}

