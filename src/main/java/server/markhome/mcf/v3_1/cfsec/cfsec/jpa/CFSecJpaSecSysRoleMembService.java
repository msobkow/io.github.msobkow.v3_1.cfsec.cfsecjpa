// Description: Java 25 Spring JPA Service for SecSysRoleMemb

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
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	Service for the CFSecSecSysRoleMemb entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecSecSysRoleMembRepository to access them.
 */
@Service("cfsec31JpaSecSysRoleMembService")
public class CFSecJpaSecSysRoleMembService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaSecSysRoleMembRepository cfsec31SecSysRoleMembRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaSecSysRoleMemb, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleMemb create(CFSecJpaSecSysRoleMemb data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysRole",
				"SecSysRole",
				null);
		}
		if (data.getRequiredParentUser() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Parent",
				"Parent",
				"data.requiredParentUser",
				"data.requiredParentUser",
				"SecUser",
				"SecUser",
				null);
		}
		try {
			if(data.getPKey() != null && cfsec31SecSysRoleMembRepository.existsById((CFSecJpaSecSysRoleMembPKey)data.getPKey())) {
				return( (CFSecJpaSecSysRoleMemb)(cfsec31SecSysRoleMembRepository.findById((CFSecJpaSecSysRoleMembPKey)(data.getPKey())).get()));
			}
			if (data.getRequiredRevision() <= 0) {
				data.setRequiredRevision(1);
			}
			LocalDateTime now = LocalDateTime.now();
			data.setCreatedAt(now);
			data.setUpdatedAt(now);
			return cfsec31SecSysRoleMembRepository.save(data);
		}
		catch(Exception ex) {
			throw new CFLibDbException(getClass(),
				S_ProcName,
				ex);
		}
	}

	/**
	 *	Update an existing entity.
	 *
	 *		@param	data	The entity to be updated.
	 *
	 *		@return The updated entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleMemb update(CFSecJpaSecSysRoleMemb data) {
		final String S_ProcName = "update";
		if (data == null) {
			return( null );
		}
		if (data.getPKey() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.getPKey()");
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysRole",
				"SecSysRole",
				null);
		}
		if (data.getRequiredParentUser() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Parent",
				"Parent",
				"data.requiredParentUser",
				"data.requiredParentUser",
				"SecUser",
				"SecUser",
				null);
		}
		// Ensure the entity exists and that the revision matches
		CFSecJpaSecSysRoleMemb existing = cfsec31SecSysRoleMembRepository.findById((CFSecJpaSecSysRoleMembPKey)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecSecSysRoleMemb to existing object
		// Apply data columns of CFSecSecSysRoleMemb to existing object
		// Update the audit columns
		data.setUpdatedAt(LocalDateTime.now());
		// Save the changes we've made
		return cfsec31SecSysRoleMembRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleMemb find(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId,
		@Param("loginId") $implIJavaAtomType$ requiredLoginId) {
		return( cfsec31SecSysRoleMembRepository.get(requiredSecSysRoleId,
			requiredLoginId));
	}

	/**
	 *	ICFSecSecSysRoleMembPKey based find method for object-based access.
	 *
	 *		@param key The key of the entity to be find.
	 *
	 *		@return The entity find, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleMemb find(ICFSecSecSysRoleMembPKey key) {
		return( cfsec31SecSysRoleMembRepository.get(key.getRequiredSecSysRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> findAll() {
		return( cfsec31SecSysRoleMembRepository.findAll() );
	}

	// CFSecSecSysRoleMemb specified index finders

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecSysRoleMembBySysRoleIdxKey as arguments.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleMemb&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> findBySysRoleIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId) {
		return( cfsec31SecSysRoleMembRepository.findBySysRoleIdx(requiredSecSysRoleId));
	}

	/**
	 *	ICFSecSecSysRoleMembBySysRoleIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleMembBySysRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> findBySysRoleIdx(ICFSecSecSysRoleMembBySysRoleIdxKey key) {
		return( cfsec31SecSysRoleMembRepository.findBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecSysRoleMembByLoginIdxKey as arguments.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleMemb&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> findByLoginIdx(@Param("loginId") $implIJavaAtomType$ requiredLoginId) {
		return( cfsec31SecSysRoleMembRepository.findByLoginIdx(requiredLoginId));
	}

	/**
	 *	ICFSecSecSysRoleMembByLoginIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleMembByLoginIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> findByLoginIdx(ICFSecSecSysRoleMembByLoginIdxKey key) {
		return( cfsec31SecSysRoleMembRepository.findByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecSecSysRoleMemb specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleMemb lockByIdIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId,
		@Param("loginId") $implIJavaAtomType$ requiredLoginId) {
		return( cfsec31SecSysRoleMembRepository.lockByIdIdx(requiredSecSysRoleId,
			requiredLoginId));
	}

	/**
	 *	ICFSecSecSysRoleMembPKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleMemb lockByIdIdx(ICFSecSecSysRoleMembPKey key) {
		return( cfsec31SecSysRoleMembRepository.lockByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> lockBySysRoleIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId) {
		return( cfsec31SecSysRoleMembRepository.lockBySysRoleIdx(requiredSecSysRoleId));
	}

	/**
	 *	ICFSecSecSysRoleMembBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> lockBySysRoleIdx(ICFSecSecSysRoleMembBySysRoleIdxKey key) {
		return( cfsec31SecSysRoleMembRepository.lockBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> lockByLoginIdx(@Param("loginId") $implIJavaAtomType$ requiredLoginId) {
		return( cfsec31SecSysRoleMembRepository.lockByLoginIdx(requiredLoginId));
	}

	/**
	 *	ICFSecSecSysRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleMemb> lockByLoginIdx(ICFSecSecSysRoleMembByLoginIdxKey key) {
		return( cfsec31SecSysRoleMembRepository.lockByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecSecSysRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredLoginId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId,
		@Param("loginId") $implIJavaAtomType$ requiredLoginId) {
		cfsec31SecSysRoleMembRepository.deleteByIdIdx(requiredSecSysRoleId,
			requiredLoginId);
	}

	/**
	 *	ICFSecSecSysRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleMembByIdIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(ICFSecSecSysRoleMembPKey key) {
		cfsec31SecSysRoleMembRepository.deleteByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredLoginId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySysRoleIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId) {
		cfsec31SecSysRoleMembRepository.deleteBySysRoleIdx(requiredSecSysRoleId);
	}

	/**
	 *	ICFSecSecSysRoleMembBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleMembBySysRoleIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySysRoleIdx(ICFSecSecSysRoleMembBySysRoleIdxKey key) {
		cfsec31SecSysRoleMembRepository.deleteBySysRoleIdx(key.getRequiredSecSysRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByLoginIdx(@Param("loginId") $implIJavaAtomType$ requiredLoginId) {
		cfsec31SecSysRoleMembRepository.deleteByLoginIdx(requiredLoginId);
	}

	/**
	 *	ICFSecSecSysRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleMembByLoginIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByLoginIdx(ICFSecSecSysRoleMembByLoginIdxKey key) {
		cfsec31SecSysRoleMembRepository.deleteByLoginIdx(key.getRequiredLoginId());
	}

}
