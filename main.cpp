#include <iostream>
#include <stdexcept>

#include "asset.h"
#include "asset_database.h"
#include "rule.h"
#include "lua_evaluate.h"
#include "extended_rules.h"
#include "rule_factory.h"

bool assetUT () {
    try {
        //BasicAsset a; // this causes g++ error, as expected
        BasicAsset b ("id-1", "active", "device", "rackcontroller");
        if (b.getId () != "id-1")
            return false;
        if (b.getStatus () != BasicAsset::Status::Active)
            return false;
        if (b.getType () != BasicAsset::Type::Type_Device)
            return false;
        if (b.getSubtype () != BasicAsset::Subtype::Subtype_RackController)
            return false;
        if (b.getStatusString () != "active")
            return false;
        if (b.getTypeString () != "device")
            return false;
        if (b.getSubtypeString () != "rackcontroller")
            return false;
        b.setStatus ("nonactive");
        if (b.getStatus () != BasicAsset::Status::Nonactive)
            return false;
        b.setType ("vm");
        if (b.getType () != BasicAsset::Type::Type_VM)
            return false;
        b.setSubtype ("vmwarevm");
        if (b.getSubtype () != BasicAsset::Subtype::Subtype_VMWareVM)
            return false;
        BasicAsset bb (b);
        if (!b.compare (bb))
            return false;
        if (bb.getId () != "id-1")
            return false;
        if (bb.getType () != BasicAsset::Type::Type_VM)
            return false;
        bb.setType ("device");
        if (bb.getType () != BasicAsset::Type::Type_Device)
            return false;
        if (b.getType () != BasicAsset::Type::Type_VM)
            return false;
        if (b.compare (bb))
            return false;
    } catch (std::exception &e) {
        return false;
    }
    try {
        BasicAsset c ("id-2", "invalid", "device", "rackcontroller");
        return false;
    } catch (std::exception &e) {
        // exception is expected
    }
    try {
        BasicAsset d ("id-3", "active", "invalid", "rackcontroller");
        return false;
    } catch (std::exception &e) {
        // exception is expected
    }
    try {
        BasicAsset e ("id-4", "active", "device", "invalid");
        return false;
    } catch (std::exception &e) {
        // exception is expected
    }
    try {
        ExtendedAsset f ("id-5", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
        if (f.getName () != "MyRack")
            return false;
        if (f.getParentId () != "id-1")
            return false;
        if (f.getPriority () != 1)
            return false;
        if (f.getPriorityString () != "P1")
            return false;
        ExtendedAsset g ("id-6", "active", "device", "rackcontroller", "MyRack", "parent-1", "P2");
        if (f.compare (g))
            return false;
        if (g.getPriority () != 2)
            return false;
        if (g.getPriorityString () != "P2")
            return false;
        g.setName ("MyNewRack");
        if (g.getName () != "MyNewRack")
            return false;
        g.setParentId ("parent-2");
        if (g.getParentId () != "parent-2")
            return false;
        g.setPriority ("P3");
        if (g.getPriority () != 3)
            return false;
        g.setPriority (4);
        if (g.getPriority () != 4)
            return false;
        ExtendedAsset gg (g);
        if (!g.compare (gg))
            return false;
        if (gg.getId () != "id-6")
            return false;
        if (gg.getName () != "MyNewRack")
            return false;
        gg.setName ("MyOldRack");
        if (gg.getName () != "MyOldRack")
            return false;
        if (g.getName () != "MyNewRack")
            return false;
        if (g.compare (gg))
            return false;
    } catch (std::exception &e) {
        return false;
    }
    try {
        FullAsset h ("id-7", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"},
                {"aux2", "aval2"}}, {});
        if (h.getAuxItem ("aux2") != "aval2")
            return false;
        if (!h.getAuxItem ("aval3").empty ())
            return false;
        if (!h.getExtItem ("eval1").empty ())
            return false;
        h.setAuxItem ("aux4", "aval4");
        if (h.getAuxItem ("aux4") != "aval4")
            return false;
        h.setExtItem ("ext5", "eval5");
        if (h.getExtItem ("ext5") != "eval5")
            return false;
        h.setExt ({{"ext1", "eval1"}});
        if (h.getExtItem ("ext1") != "eval1")
            return false;
        if (h.getExtItem ("ext5") == "eval5")
            return false;
        if (h.getItem ("aux2") != "aval2")
            return false;
        if (h.getItem ("ext1") != "eval1")
            return false;
        if (!h.getItem ("notthere").empty ())
            return false;
        FullAsset hh (h);
        if (!h.compare (hh))
            return false;
        if (hh.getExtItem ("ext1") != "eval1")
            return false;
        if (!hh.getExtItem ("ext6").empty ())
            return false;
        hh.setExtItem ("ext6", "eval6");
        if (hh.getExtItem ("ext6") != "eval6")
            return false;
        if (!h.getExtItem ("ext6").empty ())
            return false;
        if (h.compare (hh))
            return false;
    } catch (std::exception &e) {
        return false;
    }
    return true;
}

bool assetDatabaseUT1 () {
    BasicAsset ba1 ("id-1", "active", "device", "rackcontroller");
    BasicAsset ba2 ("id-2", "active", "device", "rackcontroller");
    BasicAsset ba3 ("id-3", "active", "device", "rackcontroller");
    BasicAsset ba4 ("id-4", "active", "device", "rackcontroller");
    ExtendedAsset ea1 ("id-5", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    ExtendedAsset ea2 ("id-6", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    ExtendedAsset ea3 ("id-7", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    ExtendedAsset ea4 ("id-8", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    FullAsset fa1 ("id-9", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    FullAsset fa2 ("id-10", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    FullAsset fa3 ("id-11", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    FullAsset fa4 ("id-12", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    std::shared_ptr<BasicAsset> bap4 = std::make_shared<BasicAsset> (ba4);
    std::shared_ptr<ExtendedAsset> eap4 = std::make_shared<ExtendedAsset> (ea4);
    std::shared_ptr<FullAsset> fap4 = std::make_shared<FullAsset> (fa4);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ba1);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ba2);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ba3);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (bap4);
    auto b = BasicAssetDatabase::getInstance ().getAsset ("id-1");
    if (b == nullptr)
        return false;
    if (b->getId () != "id-1")
        return false;
    if (b->getStatusString () != "active")
        return false;
    if (b->getTypeString () != "device")
        return false;
    if (b->getSubtypeString () != "rackcontroller")
        return false;
    b = BasicAssetDatabase::getInstance ().getAsset ("id-4");
    if (b == nullptr)
        return false;
    if (b->getId () != "id-4")
        return false;
    if (b->getStatusString () != "active")
        return false;
    if (b->getTypeString () != "device")
        return false;
    if (b->getSubtypeString () != "rackcontroller")
        return false;
    b = BasicAssetDatabase::getInstance ().getAsset ("id-0");
    if (b != nullptr)
        return false;
    auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-1");
    if (e != nullptr)
        return false;
    auto f = FullAssetDatabase::getInstance ().getAsset ("id-1");
    if (f != nullptr)
        return false;
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (ea1);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (ea2);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (eap4);
    e = ExtendedAssetDatabase::getInstance ().getAsset ("id-5");
    if (e == nullptr)
        return false;
    e = ExtendedAssetDatabase::getInstance ().getAsset ("id-8");
    if (e == nullptr)
        return false;
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa1);
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa2);
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fap4);
    f = FullAssetDatabase::getInstance ().getAsset ("id-9");
    if (f == nullptr)
        return false;
    f = FullAssetDatabase::getInstance ().getAsset ("id-12");
    if (f == nullptr)
        return false;
    // mixing basic assets into extended and full asset DB is unsupported
    // ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (ba1);
    // ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (bap4);
    // FullAssetDatabase::getInstance ().insertOrUpdateAsset (ba1);
    // FullAssetDatabase::getInstance ().insertOrUpdateAsset (bap4);
    // while it's eligible the other way around
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ea1);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (eap4);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (fa1);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (fap4);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (fa1);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (fap4);
    b = BasicAssetDatabase::getInstance ().getAsset ("id-5");
    if (b == nullptr)
        return false;
    b = BasicAssetDatabase::getInstance ().getAsset ("id-8");
    if (b == nullptr)
        return false;
    // while it is OK to insert assets via value, make_shared strips them to base class so extended attributes are lost
    b = BasicAssetDatabase::getInstance ().getAsset ("id-9");
    if (b == nullptr)
        return false;
    // but not when assets are passed as shared_ptrs
    b = BasicAssetDatabase::getInstance ().getAsset ("id-12");
    if (b == nullptr)
        return false;
    try {
        f = std::dynamic_pointer_cast<FullAsset>(b);
        if (f == nullptr)
            return false;
        if (f->getItem ("aux1") != "aval1")
            return false;
    } catch (std::exception &e) {
        return false;
    }
    e = ExtendedAssetDatabase::getInstance ().getAsset ("id-9");
    if (e == nullptr)
        return false;
    e = ExtendedAssetDatabase::getInstance ().getAsset ("id-12");
    if (e == nullptr)
        return false;
    try {
        f = std::dynamic_pointer_cast<FullAsset>(e);
        if (f == nullptr)
            return false;
        if (f->getItem ("aux1") != "aval1")
            return false;
    } catch (std::exception &e) {
        return false;
    }
    auto g = FullAssetDatabase::getInstance ().getAssetForManipulation ("id-10");
    if (g->getAuxItem ("aux5") != "")
        return false;
    g->setAuxItem ("aux5", "aval5");
    auto h = FullAssetDatabase::getInstance ().getAsset ("id-10");
    if (h->getAuxItem ("aux5") != "aval5")
        return false;
    return true;
}

bool assetDatabaseUT2 () {
    // access assets outside of previous function scope
    auto b = BasicAssetDatabase::getInstance ().getAsset ("id-1");
    if (b == nullptr)
        return false;
    if (b->getId () != "id-1")
        return false;
    if (b->getStatusString () != "active")
        return false;
    if (b->getTypeString () != "device")
        return false;
    if (b->getSubtypeString () != "rackcontroller")
        return false;
    b = BasicAssetDatabase::getInstance ().getAsset ("id-4");
    if (b == nullptr)
        return false;
    if (b->getId () != "id-4")
        return false;
    if (b->getStatusString () != "active")
        return false;
    if (b->getTypeString () != "device")
        return false;
    if (b->getSubtypeString () != "rackcontroller")
        return false;
    b = BasicAssetDatabase::getInstance ().getAsset ("id-0");
    if (b != nullptr)
        return false;
    auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-1");
    if (e != nullptr)
        return false;
    auto f = FullAssetDatabase::getInstance ().getAsset ("id-1");
    if (f != nullptr)
        return false;
    return true;
}

bool ruleUT () {
    // Rule r; // compiler error, Rule is abstract
    RuleTest rt ("metric@asset1", {"metric1"}, {"asset1"}, {"CAT_ALL"}, {{"ok", {{"no_action"}, "critical", "ok_description"}}});
    rt.setGlobalVariables ({{"var1", "val1"}, {"var2", "val2"}});
    if (rt.whoami () != "test")
        return false;
    if (rt.evaluate ({})[0] != "eval")
        return false;
    std::string json = rt.getJsonRule ();
    json.erase (remove_if (json.begin (), json.end (), isspace), json.end ());
    if (json != std::string ("{\"test\":{\"name\":\"metric@asset1\",\"categories\":[\"CAT_ALL\"],\"metrics\":[\"") +
            "metric1\"],\"results\":[{\"ok\":{\"action\":[],\"severity\":\"critical\",\"description\":\"" +
            "ok_description\",\"threshold_name\":\"\"}}],\"assets\":[\"asset1\"],\"values\":[{\"var1\":\"val1\"},{\"" +
            "var2\":\"val2\"}]}}")
        return false;
    RuleTest rt2 (json);
    RuleTest rt3 (json);
    if (!rt2.compare (rt3))
        return false;
    std::string json3 = rt3.getJsonRule ();
    RuleTest rt4 (json3);
    json3.erase (remove_if (json3.begin (), json3.end (), isspace), json3.end ());
    std::string json4 = rt4.getJsonRule ();
    json4.erase (remove_if (json4.begin (), json4.end (), isspace), json4.end ());
    if (json3 != json || json3 != json4)
        return false;
    FlexibleRule ("metric@asset2", {"metric1"}, {"asset2"}, {"CAT_ALL"}, {{"ok", {{"no_action"}, "critical",
            "ok_description"}}}, "function main () return ok end", {{"var1", "val1"}});
    return true;
}

bool ruleFactoryUT () {
    // flexible rule sts-voltage@device_sts.rule
    std::string json1 = std::string ("{ \"flexible\" : { \"name\" : \"sts-voltage@__name__\", \"description\" : \"") +
            "TRANSLATE_LUA (The STS/ATS voltage is out of tolerance)\", \"categories\" : [\"CAT_OTHER\", \"CAT_ALL\"]" +
            ", \"metrics\" : [\"status.input.1.voltage\", \"status.input.2.voltage\"], \"assets\" : [\"__name__\"" +
            "], \"results\" : [ { \"high_warning\" : { \"action\" : [ ], \"severity\" : \"WARNING\", \"description\" " +
            ": \"none\" } } ], \"evaluation\" : \" function main (i1," + " i2) if i1 == 'good' and i2 == 'good' then return OK, string.format ('{ \\\"key\\\": \\\"TRANSLATE_LUA (" + "Voltage status of both inputs of {{NAME}} is good.)\\\", \\\"variables\\\": {\\\"NAME\\\": \\\"NAME\\\"" + "}}') end if i1 == 'good' then return WARNING, string.format ('{ \\\"key\\\": \\\"TRANSLATE_LUA (Input 2 " + "voltage status of {{NAME}} is out of tolerance ({{i2}})!)\\\", \\\"variables\\\": {\\\"NAME\\\": \\\"" + "NAME\\\", \\\"i2\\\" : \\\"%s\\\"}}', i2) end if i2 == 'good' then return WARNING, string.format ('{ " + "\\\"key\\\": \\\"TRANSLATE_LUA (Input 1 voltage status of {{NAME}} is out of tolerance ({{i1}})!)\\\", " + "\\\"variables\\\": {\\\"NAME\\\": \\\"NAME\\\", \\\"i1\\\" : \\\"%s\\\"}}', i1) end return WARNING, " + "string.format ('{ \\\"key\\\": \\\"TRANSLATE_LUA (Voltage status of both inputs is out of tolerance " + "({{i1}}, {{i2}})!)\\\", \\\"variables\\\": {\\\"i2\\\": \\\"%s\\\", \\\"i1\\\" : \\\"%s\\\"}}', i2, i1) " + "end \" } }";
    auto rule = RuleFactory::createFromJson (json1);
    if (rule->whoami () != "flexible")
        return false;
    if (rule->getName () != "sts-voltage@__name__")
        return false;
    return true;
}

int main () {
    if (!assetUT ())
        std::cout << "Asset unit tests failed" << std::endl;
    if (!assetDatabaseUT1 ())
        std::cout << "Asset database unit tests failed" << std::endl;
    if (!assetDatabaseUT2 ())
        std::cout << "Asset database unit tests failed" << std::endl;
    if (!ruleUT ())
        std::cout << "Rule unit tests failed" << std::endl;
    if (!ruleFactoryUT ())
        std::cout << "Rule factory unit tests failed" << std::endl;
    std::cout << "All tests finished" << std::endl;
    return 0;
}
