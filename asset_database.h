#ifndef __ASSET_DATABASE_GUARD__
#define __ASSET_DATABASE_GUARD__

#include <memory>
#include <map>
#include <stdexcept>

#include "asset.h"

/*
 * \brief Class that provides C++ singleton database of assets
 */
template <typename AssetT>
class AssetDatabase {
    private:
        std::map<std::string, std::shared_ptr<AssetT>> asset_database_;
        // ctor
        AssetDatabase () { };

        std::shared_ptr <AssetT> getAsset_ (const std::string &key) const {
            auto it = asset_database_.find (key);
            if (it != asset_database_.end ()) {
                return it->second;
            }
            return nullptr;
        }
    public:
        // ctors, =, instantiation
        AssetDatabase (const AssetDatabase & ad) = delete;
        AssetDatabase (AssetDatabase && ad) = delete;
        AssetDatabase & operator= (const AssetDatabase &ad) = delete;
        AssetDatabase & operator= (AssetDatabase &&ad) = delete;
        static AssetDatabase & getInstance () {
            static AssetDatabase ad;
            return ad;
        }
        // data manipulation
        /// asset getter for possible updates, user needs to check unique () to ensure at least basic thread safety
        std::shared_ptr<AssetT> getAssetForManipulation (const std::string key) { return getAsset_ (key); }
        /// getter for data extraction
        const std::shared_ptr<AssetT> getAsset (const std::string key) const { return getAsset_ (key); }
        /// insert or update, not safe for inheritance
        void insertOrUpdateAsset (AssetT asset) {
            std::string key = static_cast<BasicAsset>(asset).getId ();
            asset_database_[key] = std::make_shared<AssetT> (asset);
        }
        /// insert or update, safe for inheritance
        void insertOrUpdateAsset (std::shared_ptr<AssetT> asset) {
            if (asset != nullptr) {
                std::string key = asset->getId ();
                asset_database_[key] = asset;
            } else {
                throw std::logic_error ("Can't create null asset");
            }
        }
};

using BasicAssetDatabase = AssetDatabase<BasicAsset>;
using ExtendedAssetDatabase = AssetDatabase<ExtendedAsset>;
using FullAssetDatabase = AssetDatabase<FullAsset>;

#endif // __ASSET_DATABASE_GUARD__
