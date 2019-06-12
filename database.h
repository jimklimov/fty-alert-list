/*  =========================================================================
    database - Database

    Copyright (C) 2019 - 2019 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

#ifndef DATABASE_H_INCLUDED
#define DATABASE_H_INCLUDED

#include <memory>
#include <map>
#include <stdexcept>

class null_argument : std::runtime_error {
    public:
        null_argument () : runtime_error ("null argument") { }
};
class element_not_found : std::runtime_error {
    public:
        element_not_found () : runtime_error ("element not found") { }
};

/*
 * \brief Class that provides simple in-memory database
 */
template <typename KeyT, typename ElementT>
class GenericDatabase {
    public:
        using ElementPtr = std::shared_ptr<ElementT>;
        using DatabaseType = std::map<KeyT, ElementPtr>;
        using iterator = typename DatabaseType::iterator;
        using const_iterator = typename DatabaseType::const_iterator;
    private:
        /// database implementation, indexed by some key
        DatabaseType database_;
    protected:
        /// accessor
        iterator getElementIt (const KeyT &key) {
            return database_.find (key);
        }
        const_iterator getElementIt (const KeyT &key) const {
            return database_.find (key);
        }
    public:
        // ctors, =, instantiation
        GenericDatabase () { };
        GenericDatabase (const GenericDatabase & ad) = delete;
        GenericDatabase (GenericDatabase && ad) = delete;
        GenericDatabase & operator= (const GenericDatabase &ad) = delete;
        GenericDatabase & operator= (GenericDatabase &&ad) = delete;
        // data manipulation
        /// getter for possible updates, user needs to check unique () to ensure at least basic thread safety
        ElementPtr getElementForManipulation (const KeyT key) {
            iterator it = getElementIt (key);
            if (it != database_.end ()) {
                return getElementIt (key)->second;
            } else {
                throw element_not_found ();
            }
        }
        /// getter for data extraction
        const ElementPtr getElement (const KeyT key) const {
            const_iterator it = getElementIt (key);
            if (it != database_.end ()) {
                return getElementIt (key)->second;
            }
            throw element_not_found ();
        }
        /// insert or update, not safe for inheritance
        void insertOrUpdateElement (const KeyT key, const ElementT element) {
            database_[key] = ElementPtr (new ElementT (element));
        }
        /// insert or update, safe for inheritance
        void insertOrUpdateElement (const KeyT key, ElementPtr element) {
            if (element != nullptr) {
                database_[key] = element;
            } else {
                throw null_argument ();
            }
        }
        void deleteElement (const KeyT key) {
            iterator it = getElementIt (key);
            if (it != database_.end ()) {
                database_.erase (getElementIt (key));
            } else {
                throw element_not_found ();
            }
        }
        // iterators
        inline typename std::map<KeyT, std::shared_ptr<ElementT>>::iterator begin () noexcept { return database_.begin (); }
        inline typename std::map<KeyT, std::shared_ptr<ElementT>>::const_iterator cbegin () const noexcept { return database_.cbegin (); }
        inline typename std::map<KeyT, std::shared_ptr<ElementT>>::iterator end () noexcept { return database_.end (); }
        inline typename std::map<KeyT, std::shared_ptr<ElementT>>::const_iterator cend () const noexcept { return database_.cend (); }
};

/*
 * \brief Class that provides simple in-memory observed database
 */
template <typename KeyT, typename ElementT>
class ObservedGenericDatabase : public GenericDatabase<KeyT, ElementT> {
    using GD = GenericDatabase<KeyT,ElementT>;
    using typename GD::ElementPtr;
    using GD::end;
    public:
        using CallbackFunction = std::function<void (void)>;
    private:
        CallbackFunction on_create;
        CallbackFunction on_update;
        CallbackFunction on_delete;
    public:
        // observer manipulation
        void setOnCreate (CallbackFunction f) { on_create = f; }
        void setOnUpdate (CallbackFunction f) { on_update = f; }
        void setOnDelete (CallbackFunction f) { on_delete = f; }
        void clearOnCreate () { on_create = CallbackFunction (); }
        void clearOnUpdate () { on_update = CallbackFunction (); }
        void clearOnDelete () { on_delete = CallbackFunction (); }
        // calls
        /// throws any errors, notably element_not_found
        void insertElement (KeyT key, ElementT element) {
            GD::insertOrUpdateElement (key, element);
            if (on_create)
                on_create ();
        }
        /// throws any errors, notably element_not_found
        void insertElement (KeyT key, ElementPtr element) {
            GD::insertOrUpdateElement (key, element);
            if (on_create)
                on_create ();
        }
        /// throws any errors, notably element_not_found
        void updateElement (KeyT key, ElementT element) {
            GD::insertOrUpdateElement (key, element);
            if (on_update)
                on_update ();
        }
        /// throws any errors, notably element_not_found
        void updateElement (KeyT key, ElementPtr element) {
            GD::insertOrUpdateElement (key, element);
            if (on_update)
                on_update ();
        }
        void insertOrUpdateElement (KeyT key, ElementT element) {
            if (GD::getElementIt (key) != end ()) {
                // update
                updateElement (key, element);
            } else {
                // insert
                insertElement (key, element);
            }
        }
        void insertOrUpdateElement (KeyT key, ElementPtr element) {
            if (GD::getElementIt (key) != end ()) {
                // update
                updateElement (key, element);
            } else {
                // insert
                insertElement (key, element);
            }
        }
        /// throws any errors, notably element_not_found
        void deleteElement (KeyT key) {
            GD::deleteElement (key);
            if (on_delete)
                on_delete ();
        }
};

#endif
