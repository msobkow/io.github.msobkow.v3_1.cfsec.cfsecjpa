// Description: Java 25 Spring JPA Service for SecTentRoleMemb

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	Service for the CFSecSecTentRoleMemb entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecSecTentRoleMembRepository to access them.
 */
@Service("cfsec31JpaSecTentRoleMembService")
public class CFSecJpaSecTentRoleMembService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaSecTentRoleMembRepository cfsec31SecTentRoleMembRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaSecTentRoleMemb, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMemb create(CFSecJpaSecTentRoleMemb data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		if (data.getRequiredContainerRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerRole",
				"data.requiredContainerRole",
				"SecTentRole",
				"SecTentRole",
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
			if(data.getPKey() != null && cfsec31SecTentRoleMembRepository.existsById((CFSecJpaSecTentRoleMembPKey)data.getPKey())) {
				return( (CFSecJpaSecTentRoleMemb)(cfsec31SecTentRoleMembRepository.findById((CFSecJpaSecTentRoleMembPKey)(data.getPKey())).get()));
			}
			if (data.getRequiredRevision() <= 0) {
				data.setRequiredRevision(1);
			}
			LocalDateTime now = LocalDateTime.now();
			data.setCreatedAt(now);
			data.setUpdatedAt(now);
			return cfsec31SecTentRoleMembRepository.save(data);
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
	public CFSecJpaSecTentRoleMemb update(CFSecJpaSecTentRoleMemb data) {
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
		if (data.getRequiredContainerRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerRole",
				"data.requiredContainerRole",
				"SecTentRole",
				"SecTentRole",
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
		CFSecJpaSecTentRoleMemb existing = cfsec31SecTentRoleMembRepository.findById((CFSecJpaSecTentRoleMembPKey)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecSecTentRoleMemb to existing object
		// Apply data columns of CFSecSecTentRoleMemb to existing object
		// Update the audit columns
		data.setUpdatedAt(LocalDateTime.now());
		// Save the changes we've made
		return cfsec31SecTentRoleMembRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecTentRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMemb find(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId,
		@Param("loginId") String requiredLoginId) {
		return( cfsec31SecTentRoleMembRepository.get(requiredSecTentRoleId,
			requiredLoginId));
	}

	/**
	 *	ICFSecSecTentRoleMembPKey based find method for object-based access.
	 *
	 *		@param key The key of the entity to be find.
	 *
	 *		@return The entity find, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMemb find(ICFSecSecTentRoleMembPKey key) {
		return( cfsec31SecTentRoleMembRepository.get(key.getRequiredSecTentRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> findAll() {
		return( cfsec31SecTentRoleMembRepository.findAll() );
	}

	// CFSecSecTentRoleMemb specified index finders

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecTentRoleMembByTentRoleIdxKey as arguments.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return List&lt;CFSecJpaSecTentRoleMemb&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> findByTentRoleIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId) {
		return( cfsec31SecTentRoleMembRepository.findByTentRoleIdx(requiredSecTentRoleId));
	}

	/**
	 *	ICFSecSecTentRoleMembByTentRoleIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleMembByTentRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> findByTentRoleIdx(ICFSecSecTentRoleMembByTentRoleIdxKey key) {
		return( cfsec31SecTentRoleMembRepository.findByTentRoleIdx(key.getRequiredSecTentRoleId()));
	}

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecTentRoleMembByUserIdxKey as arguments.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return List&lt;CFSecJpaSecTentRoleMemb&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> findByUserIdx(@Param("loginId") String requiredLoginId) {
		return( cfsec31SecTentRoleMembRepository.findByUserIdx(requiredLoginId));
	}

	/**
	 *	ICFSecSecTentRoleMembByUserIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleMembByUserIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> findByUserIdx(ICFSecSecTentRoleMembByUserIdxKey key) {
		return( cfsec31SecTentRoleMembRepository.findByUserIdx(key.getRequiredLoginId()));
	}

	// CFSecSecTentRoleMemb specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMemb lockByIdIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId,
		@Param("loginId") String requiredLoginId) {
		return( cfsec31SecTentRoleMembRepository.lockByIdIdx(requiredSecTentRoleId,
			requiredLoginId));
	}

	/**
	 *	ICFSecSecTentRoleMembPKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMemb lockByIdIdx(ICFSecSecTentRoleMembPKey key) {
		return( cfsec31SecTentRoleMembRepository.lockByIdIdx(key.getRequiredSecTentRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> lockByTentRoleIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId) {
		return( cfsec31SecTentRoleMembRepository.lockByTentRoleIdx(requiredSecTentRoleId));
	}

	/**
	 *	ICFSecSecTentRoleMembByTentRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> lockByTentRoleIdx(ICFSecSecTentRoleMembByTentRoleIdxKey key) {
		return( cfsec31SecTentRoleMembRepository.lockByTentRoleIdx(key.getRequiredSecTentRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> lockByUserIdx(@Param("loginId") String requiredLoginId) {
		return( cfsec31SecTentRoleMembRepository.lockByUserIdx(requiredLoginId));
	}

	/**
	 *	ICFSecSecTentRoleMembByUserIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRoleMemb> lockByUserIdx(ICFSecSecTentRoleMembByUserIdxKey key) {
		return( cfsec31SecTentRoleMembRepository.lockByUserIdx(key.getRequiredLoginId()));
	}

	// CFSecSecTentRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *		@param requiredLoginId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId,
		@Param("loginId") String requiredLoginId) {
		cfsec31SecTentRoleMembRepository.deleteByIdIdx(requiredSecTentRoleId,
			requiredLoginId);
	}

	/**
	 *	ICFSecSecTentRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleMembByIdIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(ICFSecSecTentRoleMembPKey key) {
		cfsec31SecTentRoleMembRepository.deleteByIdIdx(key.getRequiredSecTentRoleId(), key.getRequiredLoginId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByTentRoleIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId) {
		cfsec31SecTentRoleMembRepository.deleteByTentRoleIdx(requiredSecTentRoleId);
	}

	/**
	 *	ICFSecSecTentRoleMembByTentRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleMembByTentRoleIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByTentRoleIdx(ICFSecSecTentRoleMembByTentRoleIdxKey key) {
		cfsec31SecTentRoleMembRepository.deleteByTentRoleIdx(key.getRequiredSecTentRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUserIdx(@Param("loginId") String requiredLoginId) {
		cfsec31SecTentRoleMembRepository.deleteByUserIdx(requiredLoginId);
	}

	/**
	 *	ICFSecSecTentRoleMembByUserIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleMembByUserIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUserIdx(ICFSecSecTentRoleMembByUserIdxKey key) {
		cfsec31SecTentRoleMembRepository.deleteByUserIdx(key.getRequiredLoginId());
	}

}
