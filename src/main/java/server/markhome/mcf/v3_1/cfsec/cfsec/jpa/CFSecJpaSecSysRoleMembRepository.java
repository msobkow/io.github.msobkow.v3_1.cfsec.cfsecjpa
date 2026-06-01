// Description: Java 25 Spring JPA Repository for SecSysRoleMemb

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	JpaRepository for the CFSecJpaSecSysRoleMemb entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecSysRoleMembRepository extends JpaRepository<CFSecJpaSecSysRoleMemb, CFSecJpaSecSysRoleMembPKey> {

	@Transactional
	@Modifying
	CFSecJpaSecSysRoleMemb save(CFSecJpaSecSysRoleMemb obj);

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecSysRoleMemb r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId and r.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecSysRoleMemb get(@Param("secSysRoleId") CFLibDbKeyHash256 requiredSecSysRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecSysRoleMembPKey based read method for object-based access.
	 *
	 *		@param key The key of the entity to be read.
	 *
	 *		@return The entity read, usually from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecSysRoleMemb get(ICFSecSecSysRoleMembPKey key) {
		return( get(key.getRequiredSecSysRoleId(), key.getRequiredLoginId()));
	}

	// CFSecJpaSecSysRoleMemb specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecSysRoleMembBySysRoleIdxKey as arguments.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecSysRoleMemb r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId")
	List<CFSecJpaSecSysRoleMemb> findBySysRoleIdx(@Param("secSysRoleId") CFLibDbKeyHash256 requiredSecSysRoleId);

	/**
	 *	CFSecSecSysRoleMembBySysRoleIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleMembBySysRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecSysRoleMemb> findBySysRoleIdx(ICFSecSecSysRoleMembBySysRoleIdxKey key) {
		return( findBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecSysRoleMembByLoginIdxKey as arguments.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecSysRoleMemb r where r.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecSysRoleMemb> findByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecSysRoleMembByLoginIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleMembByLoginIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecSysRoleMemb> findByLoginIdx(ICFSecSecSysRoleMembByLoginIdxKey key) {
		return( findByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecSysRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRoleMemb r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId and r.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecSysRoleMemb lockByIdIdx(@Param("secSysRoleId") CFLibDbKeyHash256 requiredSecSysRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecSysRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecSysRoleMemb lockByIdIdx(ICFSecSecSysRoleMembPKey key) {
		return( lockByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRoleMemb r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId")
	List<CFSecJpaSecSysRoleMemb> lockBySysRoleIdx(@Param("secSysRoleId") CFLibDbKeyHash256 requiredSecSysRoleId);

	/**
	 *	CFSecSecSysRoleMembBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecSysRoleMemb> lockBySysRoleIdx(ICFSecSecSysRoleMembBySysRoleIdxKey key) {
		return( lockBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRoleMemb r where r.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecSysRoleMemb> lockByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecSysRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecSysRoleMemb> lockByLoginIdx(ICFSecSecSysRoleMembByLoginIdxKey key) {
		return( lockByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecSysRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRoleMemb r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId and r.requiredParentUser.requiredLoginId = :loginId")
	void deleteByIdIdx(@Param("secSysRoleId") CFLibDbKeyHash256 requiredSecSysRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecSysRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleMembByIdIdxKey of the entity to be locked.
	 */
	default void deleteByIdIdx(ICFSecSecSysRoleMembPKey key) {
		deleteByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredLoginId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRoleMemb r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId")
	void deleteBySysRoleIdx(@Param("secSysRoleId") CFLibDbKeyHash256 requiredSecSysRoleId);

	/**
	 *	CFSecSecSysRoleMembBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleMembBySysRoleIdxKey of the entity to be locked.
	 */
	default void deleteBySysRoleIdx(ICFSecSecSysRoleMembBySysRoleIdxKey key) {
		deleteBySysRoleIdx(key.getRequiredSecSysRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRoleMemb r where r.requiredParentUser.requiredLoginId = :loginId")
	void deleteByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecSysRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleMembByLoginIdxKey of the entity to be locked.
	 */
	default void deleteByLoginIdx(ICFSecSecSysRoleMembByLoginIdxKey key) {
		deleteByLoginIdx(key.getRequiredLoginId());
	}

}
